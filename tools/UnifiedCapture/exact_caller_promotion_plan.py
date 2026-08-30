"""Promote already-observed aggregate callers to deterministic exact capture.

The input selection scopes work; it is not treated as game evidence.  Every
promoted caller must already exist in a clean retained session, and the output
CapturePlan cites that session manifest plus any existing static evidence named
by the selection row.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, digest, file_hash, validate
from uc.probe_pair import compile_probe_pair
from uc.store import read_manifest


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("schema") == "uc.capture-plan.v1":
        validate(plan, verify_sources=True)
    elif plan.get("schema") == "uc.capture-plan.v2":
        compile_probe_pair(plan)
    else:
        raise ValueError("unsupported CapturePlan schema")


def _point_rows(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    name = "points" if plan["schema"] == "uc.capture-plan.v1" else "observations"
    return {row["id"]: row for row in plan[name]}


def _entry_identity(plan: dict[str, Any], row: dict[str, Any]) -> tuple[str, int]:
    return (row["module"], int(row["rva"] if plan["schema"] == "uc.capture-plan.v1" else row["entry"]["rva"]))


def _target_point(source_id: str, source_plan: dict[str, Any], source_row: dict[str, Any],
                  target_plan: dict[str, Any], target_rows: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """Join cross-schema plans by exact entry identity, never by guessed names."""
    identity = _entry_identity(source_plan, source_row)
    preferred = [source_id, source_id + "/entry", source_id.removesuffix("/entry")]
    for candidate_id in preferred:
        candidate = target_rows.get(candidate_id)
        if candidate is not None and _entry_identity(target_plan, candidate) == identity:
            return candidate_id, candidate
    matches = [(point_id, row) for point_id, row in target_rows.items()
               if _entry_identity(target_plan, row) == identity]
    if len(matches) != 1:
        raise ValueError(f"target plan entry identity is not unique: {source_id}:{identity}")
    return matches[0]


def derive(plan_path: Path, session: Path, selection_path: Path, output: Path,
           target_plan_path: Path | None = None) -> dict[str, Any]:
    plan_path, session, selection_path, output = (Path(value).resolve() for value in
                                                   (plan_path, session, selection_path, output))
    target_plan_path = Path(target_plan_path).resolve() if target_plan_path else plan_path
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    plan, target_plan, selection = load(plan_path), load(target_plan_path), load(selection_path)
    validate_plan(plan)
    validate_plan(target_plan)
    if selection.get("schema") != "uc.exact-caller-selection.v1":
        raise ValueError("unsupported exact caller selection schema")
    manifest_path = session / "session.manifest"
    manifest, errors = read_manifest(manifest_path)
    if errors:
        raise ValueError(f"source session manifest is incomplete: {errors}")
    end = manifest[-1] if manifest else {}
    if end.get("kind") != "session_end" or end.get("cleanup") != "STOPPED_CLEAN":
        raise ValueError("source session is not cleanly sealed")
    source_hash = digest(plan)
    activations = [row for row in manifest if row.get("kind") == "plan_activation"
                   and row.get("plan_hash") == source_hash]
    if not activations:
        raise ValueError("source plan hash was not activated in the retained session")
    activation = activations[-1]
    generation = int(activation["generation"])
    bases: dict[str, int] = {}
    for binding in activation.get("bindings", []):
        module, base = binding["module"], int(binding["module_base"])
        if module in bases and bases[module] != base:
            raise ValueError(f"module base changed inside activation: {module}")
        bases[module] = base
    retention: dict[tuple[int, str], dict[str, Any]] = {}
    for record in manifest:
        if record.get("kind") == "retention_summary":
            row = record.get("retention", {})
            if "generation" in row and "point" in row:
                retention[(int(row["generation"]), row["point"])] = row
        elif record.get("kind") == "generation_point_retired":
            row = record.get("retention", {})
            if row.get("mode") in ("first_per_entry_return_address", "first_per_composite_key"):
                retention[(int(row["generation"]), row["point"])] = row
    points,target_points = _point_rows(plan),_point_rows(target_plan)
    source_id = "exact-caller-retained-session"
    if source_id in plan["sources"]:
        raise ValueError(f"source id already exists: {source_id}")
    promoted, selected_points = [], set()
    result = copy.deepcopy(target_plan)
    result["sources"][source_id] = {"path": str(manifest_path), "sha256": file_hash(manifest_path)}
    result_points = _point_rows(result)
    for point_selection in selection.get("points", []):
        point_id = point_selection.get("point")
        if point_id not in points or point_id in selected_points:
            raise ValueError(f"unknown or duplicate selected point: {point_id}")
        selected_points.add(point_id)
        target_point_id, target_point = _target_point(point_id, plan, points[point_id], target_plan, target_points)
        summary = retention.get((generation, point_id))
        source_retention = points[point_id].get("retention", {})
        if not summary or summary.get("mode") != source_retention.get("mode") or \
                summary.get("mode") not in ("first_per_entry_return_address", "first_per_composite_key"):
            raise ValueError(f"point lacks retained caller evidence: {point_id}")
        if summary.get("complete_for_caller_counts") is not True:
            raise ValueError(f"caller counts are incomplete: {point_id}")
        observed: dict[int, dict[str, Any]] = {}
        for row in summary.get("keys", []):
            address = int(row["entry_return_address"])
            aggregate = observed.setdefault(address, {"count": 0, "full_records_persisted": 0})
            aggregate["count"] += int(row.get("count", 0))
            aggregate["full_records_persisted"] += int(row.get("full_records_persisted", 0))
        destination = result_points[target_point_id].get("retention")
        if destination is None:
            if source_retention.get("mode") not in ("first_per_entry_return_address", "first_per_composite_key") or \
                    type(source_retention.get("max_keys")) is not int:
                raise ValueError(f"discovery point lacks a reusable retention policy: {point_id}")
            destination = copy.deepcopy(source_retention)
            destination.pop("exact_callers", None)
            result_points[target_point_id]["retention"]=destination
        if not isinstance(destination, dict) or destination.get("mode") != source_retention.get("mode") or \
                destination.get("key") != source_retention.get("key"):
            raise ValueError(f"target point has an incompatible retention policy: {point_id}")
        exact = {(row["module"], int(row["return_rva"])): row
                 for row in destination.get("exact_callers", [])}
        for caller in point_selection.get("callers", []):
            module = caller.get("module")
            if module not in bases or module not in plan["modules"] or module not in target_plan["modules"]:
                raise ValueError(f"selected caller module was not bound: {module}")
            if plan["modules"][module]["sha256"]!=target_plan["modules"][module]["sha256"]:
                raise ValueError(f"selected caller module differs in target plan: {module}")
            return_rva = caller.get("return_rva")
            if type(return_rva) is not int or return_rva < 0:
                raise ValueError("selected caller return_rva must be an unsigned integer")
            address = bases[module] + return_rva
            evidence = observed.get(address)
            if not evidence:
                raise ValueError(f"selected caller was not observed: {point_id}:{module}+{return_rva:#x}")
            if int(evidence.get("full_records_persisted", 0)) < 1:
                raise ValueError(f"selected caller lacks a persisted full sample: {point_id}:{address:#x}")
            refs = caller.get("evidence", [])
            if any(ref not in target_plan["sources"] for ref in refs):
                raise ValueError(f"selected caller refers to unknown static evidence: {point_id}")
            identity = (module, return_rva)
            if identity in exact:
                raise ValueError(f"caller is already exact-promoted: {point_id}:{module}+{return_rva:#x}")
            row = {"module": module, "return_rva": return_rva,
                   "evidence": list(dict.fromkeys([*refs, source_id]))}
            exact[identity] = row
            promoted.append({"point": point_id, "module": module, "return_rva": return_rva,
                             "target_point": target_point_id,
                             "observed_callbacks": int(evidence["count"]),
                             "persisted_samples": int(evidence["full_records_persisted"])})
        destination["exact_callers"] = [exact[key] for key in sorted(exact)]
    if not promoted:
        raise ValueError("selection contains no new exact caller")
    result["plan_id"] = target_plan["plan_id"] + "-exact-callers"
    result["plan_revision"] = int(target_plan["plan_revision"]) + 1
    validate_plan(result)
    output.mkdir(parents=True)
    derived_plan = output / "capture-plan.exact-callers.json"
    derived_plan.write_bytes(canonical(result))
    report = {"schema": "uc.exact-caller-promotion-derivation.v1",
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path), "plan_hash": source_hash},
        "target_plan": {"path": str(target_plan_path), "sha256": file_hash(target_plan_path),
                        "plan_hash": digest(target_plan)},
        "source_session": {"path": str(session), "manifest_sha256": file_hash(manifest_path),
                           "generation": generation},
        "selection": {"path": str(selection_path), "sha256": file_hash(selection_path),
                      "authority": "scope-only-not-game-evidence"},
        "plan": {"path": str(derived_plan), "sha256": file_hash(derived_plan), "plan_hash": digest(result)},
        "promoted_callers": promoted,
        "semantics": "all admitted callbacks remain counted; selected observed callers retain exact full records"}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "promoted_callers": len(promoted),
                      "plan_sha256": file_hash(derived_plan)}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--target-plan", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(derive, args.plan, args.session, args.selection, args.out, args.target_plan)
