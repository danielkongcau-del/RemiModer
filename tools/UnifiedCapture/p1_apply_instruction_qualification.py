"""Bind target-process patch contracts to arbitrary entry-only instruction probes.

Unlike the function probe-pair promotion path, this tool deliberately does not
create or require a native exit manifest.  It can therefore qualify exact call
instructions and source-verified pre-call setup blocks without pretending that
they are function entries or that they have exit semantics.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _evidence_refs(rows: list[str]) -> list[str]:
    return list(dict.fromkeys([*rows, "target-qualification"]))


def run(plan_path: Path, evidence_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    source_plan = _load(plan_path)
    envelope = _load(evidence_path)
    if source_plan.get("schema") != "uc.capture-plan.v1":
        raise ValueError("source instruction plan must be v1")
    if envelope.get("schema") != "uc.target-site-qualification-evidence.v1":
        raise ValueError("qualification evidence envelope schema")
    request, response = envelope["request"], envelope["response"]
    validate_site_qualification(request)
    if (not response.get("ok")
            or response.get("schema") != "uc.target-site-qualification-result.v1"
            or response.get("qualification_id") != request["qualification_id"]
            or response.get("capture_generation_published")):
        raise ValueError("qualification result identity or publication state is invalid")
    requested = {row["id"]: row for row in request["sites"]}
    observed = {row["id"]: row for row in response["sites"]}
    expected = {point["id"] + "/entry" for point in source_plan.get("points", [])}
    if set(requested) != expected or set(observed) != expected:
        raise ValueError("qualification result must exactly cover source instruction points")
    process_identities = []
    point_by_qualification_id = {
        point["id"] + "/entry": point for point in source_plan["points"]}
    for site_id in sorted(expected):
        source, result = requested[site_id], observed[site_id]
        point = point_by_qualification_id[site_id]
        if (source.get("module") != point.get("module")
                or source.get("rva") != point.get("rva")
                or source.get("verified_source_prefix") !=
                    point.get("expected_prefix")):
            raise ValueError(f"{site_id}: qualification request differs from source point")
        if any(result.get(key) != source.get(key)
               for key in ("module", "rva", "verified_source_prefix")):
            raise ValueError(f"{site_id}: qualification differs from source request")
        if not result.get("source_restoration_verified") or not result.get(
                "target_site_patch_verified"):
            raise ValueError(f"{site_id}: install/restoration not verified")
        patch = result["backend_patch_contract"]
        if (patch["required_redirect_span"] not in source["safe_redirect_spans"]
                or patch["relocated_span"] > source["semantic_safe_span"]
                or patch.get("probe_rva") != source["rva"]):
            raise ValueError(f"{site_id}: actual redirect exceeds source-authorized window")
        process_identities.append(patch["target_process_identity"])
    if not process_identities or any(identity != process_identities[0]
                                     for identity in process_identities[1:]):
        raise ValueError("qualified instruction sites belong to different process instances")

    sources = copy.deepcopy(source_plan["sources"])
    sources["target-qualification"] = {
        "path": str(evidence_path), "sha256": file_hash(evidence_path)}
    observations = []
    point_by_id = {point["id"]: point for point in source_plan["points"]}
    for point_id in sorted(point_by_id, key=lambda value: point_by_id[value]["rva"]):
        point = point_by_id[point_id]
        if point.get("backend") != "gum_probe":
            raise ValueError(f"{point_id}: instruction qualification accepts gum_probe only")
        qualified = observed[point_id + "/entry"]
        reads = []
        for read in point.get("reads", []):
            row = copy.deepcopy(read)
            row["evidence"] = _evidence_refs(row.get("evidence", []))
            reads.append(row)
        observation = {
            "id": point_id + "/entry", "backend": "gum_function_probe_pair",
            "module": point["module"], "instruction_site_id": point_id,
            "entry": {"rva": point["rva"],
                      "expected_prefix": point["expected_prefix"],
                      "backend_patch_contract": qualified["backend_patch_contract"],
                      "reads": reads},
            "exit_capture_requirement": "none",
            "evidence": _evidence_refs(point.get("evidence", [])),
            "capture_purpose": point.get("capture_purpose"),
            "interpretation": point.get("interpretation"),
        }
        if "retention" in point:
            observation["retention"] = copy.deepcopy(point["retention"])
        observations.append(observation)
    resources = source_plan.get("resources", {})
    plan = {
        "schema": "uc.capture-plan.v2",
        "plan_id": "target-qualified-" + source_plan["plan_id"],
        "plan_revision": source_plan["plan_revision"],
        "process_binding": process_identities[0],
        "modules": source_plan["modules"], "sources": sources,
        "resources": {
            "event_slots_per_observation": max(256, resources.get("slots_per_point", 0)),
            "call_frames_per_function": 8, "thread_nesting_limit": 64,
            "max_record_bytes": max(2048, resources.get("max_record_bytes", 0)),
            "capture_xmm": bool(resources.get("capture_xmm", False)),
        },
        "physical_site_policy": {
            "exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
            "partial_overlap": "reject",
        },
        "observations": observations,
        "scope": copy.deepcopy(source_plan.get("scope", {})),
    }
    compiled = compile_probe_pair(plan, verify_sources=True)
    out.mkdir(parents=True)
    plan_out = out / "instruction-plan.target-qualified.json"
    plan_out.write_bytes(canonical(plan))
    report = {
        "schema": "uc.instruction-qualification-application.v1",
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "qualification_evidence": {
            "path": str(evidence_path), "sha256": file_hash(evidence_path)},
        "instruction_plan": {
            "path": str(plan_out), "sha256": file_hash(plan_out),
            "plan_hash": compiled.plan_hash},
        "process_binding": process_identities[0],
        "logical_observations": len(observations),
        "physical_sites": len(compiled.sites),
        "exit_probes_activated": False,
        "activation_ready": True, "game_runtime_verified": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args.plan.resolve(), args.evidence.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "apply_instruction_qualification", error, {
            "plan": str(args.plan), "evidence": str(args.evidence)})
        raise


if __name__ == "__main__":
    run_main(main)
