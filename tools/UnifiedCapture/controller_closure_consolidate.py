"""Consolidate current controller evidence without reviving superseded gaps."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def run(role_gap_path: Path, animator_acceptance_path: Path, animator_join_path: Path,
        api_usage_path: Path, controller_caller_join_path: Path,
        occurrence_trace_path: Path, dispatch_role_path: Path, output: Path,
        causal_frontier_acceptance_path: Path | None = None,
        next_plan_path: Path | None = None) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    role_gap = _load(role_gap_path)
    acceptance = _load(animator_acceptance_path)
    animator = _load(animator_join_path)
    api = _load(api_usage_path)
    callers = _load(controller_caller_join_path)
    occurrence = _load(occurrence_trace_path)
    dispatch_role = _load(dispatch_role_path)
    frontier = _load(causal_frontier_acceptance_path) if causal_frontier_acceptance_path else None
    next_plan = _load(next_plan_path) if next_plan_path else None
    if not animator.get("checks", {}).get("all_logical_edges_static_verified"):
        raise ValueError("Animator runtime/static join is not verified")
    if not acceptance.get("accepted") or not acceptance.get("game_runtime_verified"):
        raise ValueError("Animator entry acceptance is not game-runtime verified")
    if not api.get("scope", {}).get("selectedEncryptedApiTargetsClosed"):
        raise ValueError("selected encrypted API targets are not closed")
    if not api.get("scope", {}).get("selectedBridgeInvocationAbiClosed"):
        raise ValueError("selected bridge invocation ABI is not closed")
    if not all(occurrence.get("checks", {}).values()):
        raise ValueError("ability occurrence trace failed checks")
    if not all(dispatch_role.get("checks", {}).values()):
        raise ValueError("action dispatch role derivation failed checks")
    if frontier is not None and frontier.get("schema") not in (
            "uc.entry-evidence-acceptance.v1", "uc.entry-evidence-acceptance.v2"):
        raise ValueError("unsupported causal frontier acceptance")
    if next_plan is not None and next_plan.get("schema") not in (
            "uc.capture-plan.v1", "uc.capture-plan.v2"):
        raise ValueError("unsupported next capture plan")

    summary = role_gap["summary"]
    result = {
        "schema": "uc.controller-closure-state.v1",
        "sources": {
            "role_aware_controller_gap": _source(role_gap_path),
            "animator_entry_acceptance": _source(animator_acceptance_path),
            "animator_runtime_static_join": _source(animator_join_path),
            "animator_api_usage": _source(api_usage_path),
            "controller_runtime_caller_join": _source(controller_caller_join_path),
            "modify_enter_battle_occurrence": _source(occurrence_trace_path),
            "apply_logic_move_dispatch_role": _source(dispatch_role_path),
        },
        "closed_bounded": [
            {"claim": "source-classified ability wrapper execution",
             "observed": summary["wrapper_observed"], "total": summary["wrapper_total"],
             "scope": "lossless covered controller window"},
            {"claim": "Animator declared entry membership",
             "observed": sum(row.get("status", "").startswith("OBSERVED")
                             for row in acceptance.get("points", [])),
             "total": len(acceptance.get("points", [])),
             "scope": "accepted per-point runtime windows"},
            {"claim": "source-verified Animator logical runtime edges",
             "count": animator["checks"]["logical_edge_count"]},
            {"claim": "known fixed-update driver fragment to Animator stage callsites",
             "count": animator["checks"]["catalog_anchored_edge_count"]},
            {"claim": "selected Unity encrypted invocation API target",
             "unity_slot_rva": api["invoke"]["unitySlotRva"],
             "game_target_rva": api["invoke"]["gameTargetRva"],
             "scope": "two agreeing private initializations plus disk code-head verification"},
            {"claim": "selected Animator fixed-update bridge ABI",
             "invoker_rva": api["invoke"]["invokerRva"],
             "bridge_code_rva": api["invoke"]["bridgeCodeRva"],
             "argument_registers": api["invoke"]["argumentRegisters"],
             "scope": "static native data flow; not a live invocation record"},
            {"claim": "BehaviorManager task callback dispatch",
             "scope": "runtime callsites from PushTask/RunTask to observed OnStart/OnUpdate entries"},
            {"claim": "ApplyLogicMoveAction dispatch member roles",
             "assignments": {row["method"]: row["derived_role"]
                             for row in dispatch_role["classifications"]},
             "scope": "mechanical complete-.pdata code-shape equality to source-labelled action pairs"},
            {"claim": "ModifyEnterBattleStateAction serialized scenario",
             "occurrence_count": occurrence["checks"]["scanned_occurrence_count"],
             "occurrence": occurrence["occurrences"][0],
             "scope": "selected authoritative Remielle ability set; not runtime execution"},
        ],
        "classified_not_gameplay_repetition_gaps": [
            {"claim": "source-declared nativeImplementation members not observed",
             "observed": summary["native_implementation_observed"],
             "total": summary["native_implementation_total"],
             "policy": "do not repeat gameplay solely to force an alternate implementation path"},
        ],
        "offline_open": [
            {"claim": "remaining controller runtime caller identities",
             "unresolved_rows": callers["summary"]["unresolved_rows"],
             "reason": "exact callsite evidence exists but no harvested managed method identity is available"},
        ],
        "runtime_open": [
            {"claim": "live selected Unity bridge invocation for the current game instance",
             "reason": "static ABI is closed but api.invoke.liveInvocationObserved is false"},
            {"claim": "same-instance Animator stage to parameter-consumer causality"},
            {"claim": "Task/Ability to Animator cross-thread scheduling causality"},
            {"claim": "native object lifecycle to Remielle entity identity"},
            {"claim": "task reset lifecycle for selected parameter tasks"},
            {"claim": "ordinary special independent runtime coverage"},
            {"claim": "per-move attribution and complete call/return pairing"},
        ],
        "superseded_gap_statements": [
            {"statement": "UnityPlayer invoke API final target is unresolved",
             "superseded_by": "animator-api-usage v3 selectedEncryptedApiTargetsClosed and selectedBridgeInvocationAbiClosed"},
            {"statement": "all unobserved HCB/BHCI ability entries require more gameplay",
             "superseded_by": "source-declared wrapper/nativeImplementation role separation"},
        ],
        "next_work": [
            "separate reset/lifecycle and same-instance causal probes into one reusable next capture plan",
            "retain ModifyEnterBattleStateAction as chapter AirCombat coverage, not a normal trial repetition request",
            "do not block next plan on unnamed engine/ECS caller ranges whose exact callsites are already preserved",
        ],
        "runtime_required_now": False,
        "complete_controller": False,
    }
    if frontier is not None:
        result["sources"]["causal_frontier_acceptance"] = _source(causal_frontier_acceptance_path)
        definitive = [row for row in frontier.get("points", []) if row.get("status") in
                      ("OBSERVED", "OBSERVED_AGGREGATED_CALLERS",
                       "NOT_OBSERVED_IN_COVERED_WINDOW")]
        unknown = [row for row in frontier.get("points", []) if row.get("status", "").startswith("UNKNOWN")]
        not_observed = [row for row in definitive
                        if row.get("status") == "NOT_OBSERVED_IN_COVERED_WINDOW"]
        result["closed_bounded"].append({
            "claim": "causal-frontier point coverage",
            "definitive_points": len(definitive),
            "observed_points": len(definitive) - len(not_observed),
            "not_observed_points": len(not_observed),
            "total_points": len(frontier.get("points", [])),
            "scope": "clean sealed session; per-point status retains independent loss qualification",
        })
        result["runtime_observation_state"] = {
            "unknown_points": [{"point": row["point"], "status": row["status"]} for row in unknown],
            "covered_not_observed_points": [row["point"] for row in not_observed],
            "global_acceptance": frontier.get("accepted"),
            "global_acceptance_reason":
                f"all points must be definitive; {len(unknown)} lossy points keep global acceptance false",
        }
    if next_plan is not None:
        if frontier is None:
            raise ValueError("next capture plan requires causal frontier acceptance")
        result["sources"]["next_capture_plan"] = _source(next_plan_path)
        retained = [row["id"] for row in next_plan.get("points", next_plan.get("observations", []))
                    if row.get("retention")]
        result["next_capture"] = {
            "plan_id": next_plan.get("plan_id"), "plan_revision": next_plan.get("plan_revision"),
            "points": len(next_plan.get("points", next_plan.get("observations", []))),
            "aggregate_caller_retention_points": retained,
            "purpose": "replace the five lossy high-frequency streams with exact caller counts and one raw sample per caller",
        }
        result["next_work"] = [
            "run the prepared retained plan once in the normal trial without changing protection or unsafe-mode settings",
            "use linked checkpoints for one broad controller action sequence; do not repeat isolated micro-captures",
            "promote only evidence-discovered callers that still require exact per-callback or entry/leave capture",
        ]
        result["runtime_required_now"] = True
    output.mkdir(parents=True)
    artifact = output / "controller-closure-state.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-closure-state-report.v1",
              "artifact": _source(artifact),
              "closed_bounded_count": len(result["closed_bounded"]),
              "offline_open_count": len(result["offline_open"]),
              "runtime_open_count": len(result["runtime_open"]),
              "runtime_required_now": result["runtime_required_now"], "complete_controller": False}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role-gap", type=Path, required=True)
    parser.add_argument("--animator-acceptance", type=Path, required=True)
    parser.add_argument("--animator-join", type=Path, required=True)
    parser.add_argument("--api-usage", type=Path, required=True)
    parser.add_argument("--controller-caller-join", type=Path, required=True)
    parser.add_argument("--occurrence-trace", type=Path, required=True)
    parser.add_argument("--dispatch-role", type=Path, required=True)
    parser.add_argument("--causal-frontier-acceptance", type=Path)
    parser.add_argument("--next-plan", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.role_gap.resolve(), args.animator_acceptance.resolve(), args.animator_join.resolve(),
        args.api_usage.resolve(), args.controller_caller_join.resolve(), args.occurrence_trace.resolve(),
        args.dispatch_role.resolve(), args.out.resolve(),
        args.causal_frontier_acceptance.resolve() if args.causal_frontier_acceptance else None,
        args.next_plan.resolve() if args.next_plan else None)
