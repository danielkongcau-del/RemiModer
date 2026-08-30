"""Prepare mechanically proven caller-continuation qualification sites.

The input must already contain evidence-backed exact callers.  This tool does
not select callers and does not claim a complete callee exit set.  It proves a
bounded source fact for each selected return RVA and emits a target-process
patch/restore qualification request.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE
from uc.probe_pair import compile_probe_pair


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _module_source(plan: dict, alias: str) -> tuple[str, Path]:
    digest = plan["modules"][alias]["sha256"]
    rows = [(sid, Path(row["path"]).resolve()) for sid, row in plan["sources"].items()
            if row.get("sha256") == digest]
    if len(rows) != 1:
        raise ValueError(f"{alias}: expected one source with the module hash")
    return rows[0]


def _site_id(module: str, return_rva: int) -> str:
    safe = hashlib.sha256(f"{module}:{return_rva:x}".encode()).hexdigest()[:16]
    return f"caller-continuation-{safe}"


def _candidate(image: NativePE, module: str, return_rva: int) -> dict:
    owner = image.containing(return_rva - 1) if return_rva else None
    if owner is None:
        raise ValueError(f"{module}+{return_rva:#x}: no pdata owner for predecessor")
    instructions = image.decode(owner)["instructions"]
    predecessors = [row for row in instructions if row["rva"] + row["size"] == return_rva]
    if len(predecessors) != 1 or predecessors[0]["mnemonic"] != "call" or \
            "call" not in predecessors[0].get("groups", []):
        raise ValueError(f"{module}+{return_rva:#x}: unique predecessor call not proven")
    predecessor = predecessors[0]
    by_rva = {row["rva"]: row for row in instructions}
    cursor = return_rva
    while cursor - return_rva < 16:
        instruction = by_rva.get(cursor)
        if instruction is None:
            raise ValueError(f"{module}+{return_rva:#x}: no 16-byte whole-instruction continuation window")
        cursor += instruction["size"]
    semantic_span = cursor - return_rva
    if semantic_span > 32:
        raise ValueError(f"{module}+{return_rva:#x}: semantic window exceeds qualification prefix")
    prefix = image.bytes_at(return_rva, 32)
    return {
        "id": _site_id(module, return_rva), "module": module, "return_rva": return_rva,
        "expected_prefix": prefix.hex(),
        "predecessor_call": {
            "callsite_rva": predecessor["rva"], "instruction_size": predecessor["size"],
            "instruction_bytes": predecessor["bytes"],
            "call_kind": "direct" if predecessor.get("direct_target_rva") is not None else "indirect",
        },
        "source_contract": {
            "instruction_boundary_verified_by": "capstone",
            "predecessor_call_ends_at_return_rva": True,
            "relocation_window_instruction_complete": True,
            "direct_interior_edge_free": True,
            "semantic_safe_span": semantic_span,
        },
    }


def run(plan_path: Path, output: Path) -> dict:
    plan_path, output = plan_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    plan = _load(plan_path)
    if plan.get("schema") != "uc.capture-plan.v2":
        raise ValueError("caller continuations require a v2 exact-caller plan")
    compile_probe_pair(plan)
    images: dict[str, NativePE] = {}
    source_ids: dict[str, str] = {}
    associations: dict[tuple[str, int], dict] = {}
    point_keys: dict[str, list[tuple[str, int]]] = {}
    blocked_points: dict[str, list[str]] = {}
    ineligible_callers: list[dict] = []
    for observation in plan.get("observations", []):
        if observation.get("completion") is not None:
            raise ValueError(f"{observation['id']}: plan already contains completion sites")
        exact = observation.get("retention", {}).get("exact_callers", [])
        for caller in exact:
            module, return_rva = caller["module"], int(caller["return_rva"])
            if module not in images:
                source_ids[module], source_path = _module_source(plan, module)
                images[module] = NativePE(source_path)
            key = (module, return_rva)
            point_keys.setdefault(observation["id"], []).append(key)
            row = associations.get(key)
            if row is None:
                try:
                    row = _candidate(images[module], module, return_rva)
                except ValueError as error:
                    reason = str(error)
                    blocked_points.setdefault(observation["id"], []).append(reason)
                    ineligible_callers.append({"point": observation["id"], "module": module,
                                               "return_rva": return_rva, "reason": reason})
                    continue
                row["observations"] = []
                row["source_evidence"] = [source_ids[module]]
                associations[key] = row
            row["observations"].append(observation["id"])
    if not point_keys:
        raise ValueError("plan contains no exact callers")
    # One whole-module direct-edge scan per module, not one scan per site.
    by_module: dict[str, set[int]] = {}
    for row in associations.values():
        begin, span = row["return_rva"], row["source_contract"]["semantic_safe_span"]
        by_module.setdefault(row["module"], set()).update(range(begin + 1, begin + span))
    for module, targets in by_module.items():
        edges = images[module].direct_control_xrefs(targets)
        for edge in edges:
            for key, row in associations.items():
                if row["module"] == module and row["return_rva"] < edge["target_rva"] < \
                        row["return_rva"] + row["source_contract"]["semantic_safe_span"]:
                    reason = f"direct edge enters continuation interior at {module}+{edge['target_rva']:#x}"
                    for point_id in row["observations"]:
                        blocked_points.setdefault(point_id, []).append(reason)
                        ineligible_callers.append({"point": point_id, "module": key[0],
                                                   "return_rva": key[1], "reason": reason})
    all_ordered = sorted(associations.values(), key=lambda row: (row["module"], row["return_rva"]))
    for left, right in zip(all_ordered, all_ordered[1:]):
        if left["module"] == right["module"] and right["return_rva"] < left["return_rva"] + 16:
            reason = f"continuation reservations overlap: {left['id']} / {right['id']}"
            for row in (left, right):
                for point_id in row["observations"]:
                    blocked_points.setdefault(point_id, []).append(reason)
    # Pairing is all-or-nothing per logical observation: the compiler requires
    # its exact caller gates and continuation sites to match exactly. Unsafe
    # callers therefore leave that observation entry-only; other observations
    # may still advance in the same generation.
    for row in associations.values():
        row["observations"] = [point_id for point_id in row["observations"] if point_id not in blocked_points]
    ordered = [row for row in all_ordered if row["observations"]]
    artifact = {
        "schema": "uc.caller-continuation-candidates.v1",
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "semantics": "normal return to an observed exact callsite continuation; not a complete callee exit set",
        "selection": "inherited exact_callers only; no new caller selected",
        "sites": ordered,
        "skipped_observations": [{"point": point, "reasons": sorted(set(reasons))}
                                 for point, reasons in sorted(blocked_points.items())],
        "ineligible_callers": ineligible_callers,
    }
    output.mkdir(parents=True)
    candidate_path = output / "caller-continuation-candidates.json"
    candidate_path.write_bytes(canonical(artifact))
    if not ordered:
        report = {
            "schema": "uc.caller-continuation-preparation-report.v1",
            "candidates": {"path": str(candidate_path), "sha256": file_hash(candidate_path)},
            "qualification_request": None, "physical_sites": 0, "logical_subscriptions": 0,
            "skipped_observations": len(blocked_points), "activation_ready": False,
            "next": "no wholly safe continuation set; retain entry-only evidence and inspect the recorded reasons",
        }
        (output / "report.json").write_bytes(canonical(report));print(json.dumps(report, ensure_ascii=False))
        return report
    modules = {row["module"]: plan["modules"][row["module"]] for row in ordered}
    qualification = {
        "schema": "uc.probe-site-qualification.v1",
        "qualification_id": "caller-continuations-" + file_hash(plan_path)[:16],
        "modules": modules,
        "sites": [{
            "id": row["id"], "module": row["module"], "rva": row["return_rva"],
            "verified_source_prefix": row["expected_prefix"],
            "semantic_safe_span": row["source_contract"]["semantic_safe_span"],
            "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True,
        } for row in ordered],
    }
    request_path = output / "qualification-request.json"
    request_path.write_bytes(canonical(qualification))
    report = {
        "schema": "uc.caller-continuation-preparation-report.v1",
        "candidates": {"path": str(candidate_path), "sha256": file_hash(candidate_path)},
        "qualification_request": {"path": str(request_path), "sha256": file_hash(request_path)},
        "physical_sites": len(ordered),
        "logical_subscriptions": sum(len(row["observations"]) for row in ordered),
        "skipped_observations": len(blocked_points),
        "activation_ready": False, "next": "target-process qualify-sites then apply qualification",
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.plan, args.out)
