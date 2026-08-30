"""Overlay accepted controller runtime evidence onto the immutable base ledger."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _point(function_id: str) -> str:
    return f"{function_id}/entry"


def run(base_units_path: Path, controller_analysis_path: Path,
        animator_acceptance_path: Path, animator_join_path: Path,
        output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    base = _load(base_units_path)
    controller = _load(controller_analysis_path)
    animator = _load(animator_acceptance_path)
    join = _load(animator_join_path)
    if not controller.get("lossless") or controller.get("manifest_errors"):
        raise ValueError("controller analysis is not a lossless accepted source")
    if not animator.get("accepted") or not animator.get("game_runtime_verified"):
        raise ValueError("Animator acceptance is not game-runtime verified")
    if not join.get("checks", {}).get("all_logical_edges_static_verified"):
        raise ValueError("Animator logical runtime edges failed static verification")

    units = copy.deepcopy(base)
    units["schema"] = "uc.controller-runtime-units.v2"
    units["sources"]["base-runtime-units"] = _source(base_units_path)
    units["sources"]["controller-generation-1-runtime"] = _source(controller_analysis_path)
    units["sources"]["animator-stage-runtime"] = _source(animator_acceptance_path)
    units["sources"]["animator-runtime-static-join"] = _source(animator_join_path)
    observed_controller = set(controller["observed_points"])
    observed_animator = {row["point"] for row in animator["points"] if row["status"].startswith("OBSERVED")}

    unit_summaries = []
    for unit in units["units"]:
        configured = [_point(fid) for fid in unit["function_ids"]]
        if unit["id"] == "D0-set-ability-special-entry":
            observed = sorted(set(configured) & observed_controller)
            unit["activation_status"] = "VERIFIED_COMPLETE_FOR_DECLARED_ENTRY_SCOPE" if len(observed) == len(configured) else "PARTIAL"
            unit["runtime_result"] = {"configured_points": len(configured), "observed_points": observed,
                "not_observed_points": sorted(set(configured) - set(observed)), "lossless": True,
                "evidence_scope": "controller generation 1 covered overall window"}
        elif unit["id"] in ("D1-ability-action-entry-frontier", "D1-task-ecs-frontier"):
            observed = sorted(set(configured) & observed_controller)
            unit["activation_status"] = "VERIFIED_COMPLETE_FOR_DECLARED_ENTRY_SCOPE" if len(observed) == len(configured) else "PARTIAL"
            unit["runtime_result"] = {"configured_points": len(configured), "observed_count": len(observed),
                "observed_points": observed, "not_observed_points": sorted(set(configured) - set(observed)),
                "lossless": True, "evidence_scope": "controller generation 1 covered overall window"}
        elif unit["id"] == "D1-animator-stage-frontier":
            observed = sorted(set(configured) & observed_animator)
            unit["activation_status"] = "VERIFIED_COMPLETE_FOR_DECLARED_ENTRY_SCOPE" if len(observed) == len(configured) else "PARTIAL"
            unit["runtime_result"] = {"configured_points": len(configured), "observed_count": len(observed),
                "observed_points": observed, "not_observed_points": sorted(set(configured) - set(observed)),
                "lossless": all(row.get("lossless") and row.get("coverage_complete") for row in animator["points"]),
                "logical_runtime_edge_count": join["checks"]["logical_edge_count"],
                "catalog_anchored_runtime_edge_count": join["checks"]["catalog_anchored_edge_count"],
                "evidence_scope": "per-point marked window or activation generation as recorded"}
        unit_summaries.append({"id": unit["id"], "activation_status": unit["activation_status"],
                               "runtime_result": unit.get("runtime_result")})

    units["next_required_external_state"] = None
    units["next_work"] = {
        "kind": "offline_gap_reduction",
        "reason": "classify unobserved controller entries and close exact upstream/cross-system joins before selecting another runtime unit",
    }
    output.mkdir(parents=True)
    units_path = output / "runtime-units.json"
    units_path.write_bytes(canonical(units))

    ability = next(row for row in units["units"] if row["id"] == "D1-ability-action-entry-frontier")
    task = next(row for row in units["units"] if row["id"] == "D1-task-ecs-frontier")
    anim = next(row for row in units["units"] if row["id"] == "D1-animator-stage-frontier")
    gaps = {
        "schema": "uc.controller-runtime-gap-ledger.v1",
        "sources": {"runtime-units": _source(units_path),
                    "controller-generation-1-runtime": _source(controller_analysis_path),
                    "animator-stage-runtime": _source(animator_acceptance_path),
                    "animator-runtime-static-join": _source(animator_join_path)},
        "closed_bounded": [
            {"claim": "selected SetAbilitySpecialAction native entry executed", "evidence": "lossless covered window"},
            {"claim": "Animator stage declared entry membership", "observed": anim["runtime_result"]["observed_count"],
             "configured": anim["runtime_result"]["configured_points"]},
            {"claim": "source-verified Animator logical runtime edges", "count": join["checks"]["logical_edge_count"]},
            {"claim": "known fixed-update driver fragment to stage callsites", "count": join["checks"]["catalog_anchored_edge_count"]},
        ],
        "partial": [
            {"claim": "ability action entry frontier", "observed": ability["runtime_result"]["observed_count"],
             "configured": ability["runtime_result"]["configured_points"],
             "not_observed": ability["runtime_result"]["not_observed_points"]},
            {"claim": "Task/ECS and parameter entry frontier", "observed": task["runtime_result"]["observed_count"],
             "configured": task["runtime_result"]["configured_points"],
             "not_observed": task["runtime_result"]["not_observed_points"]},
            {"claim": "Animator internal call graph", "observed_runtime_edges": join["checks"]["logical_edge_count"],
             "reason": "entry evidence does not establish every outgoing branch or call/return pairing"},
        ],
        "open": [
            {"claim": "UnityPlayer fixed-update dispatch to GameAssembly InvokeOnAnimatorFixedUpdate final target"},
            {"claim": "same-instance Animator stage to parameter-consumer causality"},
            {"claim": "Task/Ability to Animator cross-thread scheduling causality"},
            {"claim": "native object lifecycle to Remielle entity identity"},
            {"claim": "ordinary special independent runtime coverage"},
            {"claim": "per-move attribution for controller entry events"},
            {"claim": "complete call/return pairing and duration"},
            {"claim": "complete controller"},
        ],
        "next_offline_tasks": [
            "classify the 17 controller points not observed in the lossless window by native signature, caller and lifecycle role",
            "join controller runtime callsites to source-identified GameAssembly callers",
            "audit the fixed-update wrapper's final indirect target and fence correlation",
            "select a combined next capture plan only for gaps that static evidence cannot close",
        ],
        "runtime_required_now": False,
    }
    gaps_path = output / "controller-runtime-gap-ledger.json"
    gaps_path.write_bytes(canonical(gaps))
    report = {"schema": "uc.controller-runtime-overlay-report.v1",
              "runtime_units": _source(units_path), "gap_ledger": _source(gaps_path),
              "units": unit_summaries, "complete_controller": False,
              "runtime_required_now": False}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-units", type=Path, required=True)
    parser.add_argument("--controller-analysis", type=Path, required=True)
    parser.add_argument("--animator-acceptance", type=Path, required=True)
    parser.add_argument("--animator-join", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.base_units.resolve(), args.controller_analysis.resolve(), args.animator_acceptance.resolve(),
        args.animator_join.resolve(), args.out.resolve())
