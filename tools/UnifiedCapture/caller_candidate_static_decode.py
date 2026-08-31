"""Decode stage-prioritized retained caller functions from source-bound PE files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def decode_candidates(profile: dict[str, Any], plan: dict[str, Any],
                      images: dict[str, NativePE]) -> dict[str, Any]:
    plan_rows = plan.get("points", []) if plan.get("schema") == "uc.capture-plan.v1" \
        else plan.get("observations", [])
    observation_rvas = {}
    for row in plan_rows:
        rva = int(row["rva"] if plan.get("schema") == "uc.capture-plan.v1"
                  else row["entry"]["rva"])
        for point_id in (row["id"], row["id"] + "/entry"):
            prior = observation_rvas.get(point_id)
            if prior is not None and prior != rva:
                raise ValueError(f"ambiguous observation entry identity: {point_id}")
            observation_rvas[point_id] = rva
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for candidate in profile.get("priority_candidates", []):
        alias = candidate["module"]
        image = images.get(alias)
        begin = int(candidate["caller_runtime_function"]["begin_rva"])
        if image is None or begin not in image.by_start:
            raise ValueError(f"priority caller lacks source-bound PDATA entry: {alias}+{begin:#x}")
        function = image.by_start[begin]
        row = grouped.setdefault((alias, begin), {"module": alias,
            "begin_rva": begin, "end_rva": function.end,
            "unwind_rva": function.unwind_rva, "candidate_callsites": []})
        callsite = int(candidate["callsite_rva"])
        target = observation_rvas.get(candidate["point"])
        row["candidate_callsites"].append({
            "callee_point": candidate["point"],
            "callsite_rva": callsite,
            "expected_target_rva": target,
            "runtime_callsite_status": candidate.get("callsite_status"),
            "dominant_action_label": candidate["dominant_action_label"],
            "action_callbacks": int(candidate["action_callbacks"]),
            "total_callbacks": int(candidate["total_callbacks"]),
        })
    output = []
    for (alias, begin), row in sorted(grouped.items()):
        image = images[alias]
        function = image.by_start[begin]
        decoded = image.decode(function)
        by_rva = {ins["rva"]: ins for ins in decoded["instructions"]}
        for callsite in row["candidate_callsites"]:
            ins = by_rva.get(callsite["callsite_rva"])
            if ins is None or "call" not in ins.get("groups", []):
                raise ValueError(f"candidate site is not a decoded call: {alias}+{callsite['callsite_rva']:#x}")
            callsite["instruction"] = ins
            direct_target = ins.get("direct_target_rva")
            callsite["callsite_kind"] = "direct" if isinstance(direct_target, int) else "indirect"
            callsite["direct_target_matches_observed_point"] = (
                isinstance(direct_target, int)
                and direct_target == callsite["expected_target_rva"])
            callsite["runtime_return_address_resolves_to_callsite"] = (
                callsite["runtime_callsite_status"] ==
                "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL")
            if isinstance(direct_target, int):
                if not callsite["direct_target_matches_observed_point"]:
                    raise ValueError("candidate direct call target differs from observed point")
            elif not callsite["runtime_return_address_resolves_to_callsite"]:
                raise ValueError("indirect candidate lacks runtime return-address callsite proof")
        raw = image.bytes_at(function.begin, function.end - function.begin)
        cfg = image.cfg(function)
        output.append({**row,
            "code_sha256": hashlib.sha256(raw).hexdigest(),
            "all_declared_bytes_decoded": decoded["all_declared_bytes_decoded"],
            "instructions": decoded["instructions"],
            "cfg": cfg,
            "direct_call_targets": sorted({ins["direct_target_rva"]
                for ins in decoded["instructions"]
                if "call" in ins.get("groups", []) and
                isinstance(ins.get("direct_target_rva"), int)}),
        })
    return {"functions": output, "summary": {
        "priority_callsites": sum(len(row["candidate_callsites"]) for row in output),
        "runtime_functions": len(output),
        "fully_decoded_functions": sum(row["all_declared_bytes_decoded"] for row in output),
        "direct_target_verified_callsites": sum(
            call["direct_target_matches_observed_point"] for row in output
            for call in row["candidate_callsites"]),
        "indirect_runtime_verified_callsites": sum(
            call["callsite_kind"] == "indirect"
            and call["runtime_return_address_resolves_to_callsite"]
            for row in output for call in row["candidate_callsites"]),
    }}


def derive(profile_path: Path, plan_path: Path, output: Path) -> dict[str, Any]:
    profile_path, plan_path, output = (Path(value).resolve()
                                       for value in (profile_path, plan_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    profile, plan = _load(profile_path), _load(plan_path)
    if profile.get("schema") != "uc.retained-caller-stage-profile.v1":
        raise ValueError("unsupported caller stage profile")
    sources = plan.get("sources", {})
    images = {}
    image_sources = {}
    for alias, module in plan.get("modules", {}).items():
        source = next((row for row in sources.values()
                       if row.get("sha256") == module.get("sha256")), None)
        if source is None:
            raise ValueError(f"module has no source-bound file: {alias}")
        path = Path(source["path"])
        if file_hash(path) != source["sha256"]:
            raise ValueError(f"module source changed: {path}")
        images[alias] = NativePE(path)
        image_sources[alias] = {"path": str(path), "sha256": source["sha256"]}
    analysis = decode_candidates(profile, plan, images)
    document = {"schema": "uc.caller-candidate-static-decode.v1",
        "sources": {
            "caller_stage_profile": {"path": str(profile_path), "sha256": file_hash(profile_path)},
            "capture_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
            "module_images": image_sources,
        }, **analysis,
        "semantic_limits": [
            "Disassembly and CFG are mechanical PE projections, not semantic names.",
            "Action-window concentration does not prove move or character ownership.",
            "Direct calls require static target equality to the observed point.",
            "Indirect calls retain runtime return-address-to-callsite proof; their static target is not asserted.",
        ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    result = {"ok": True, "output": str(output), **document["summary"]}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.profile, args.plan, args.out)


if __name__ == "__main__":
    run_main(main)
