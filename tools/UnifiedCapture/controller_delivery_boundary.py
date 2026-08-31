"""Freeze a finite Remielle controller delivery boundary from current evidence.

This is an engineering acceptance classification, not a source of gameplay
semantics.  It prevents human-readable labels, engine initialization provenance,
or exhaustive per-move replay from expanding the native controller definition
without bound.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def build(closure_path: Path, special_path: Path, branch_plan_path: Path,
          dynamic_runtime_path: Path, dynamic_body_path: Path,
          branch_ledger_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    closure = _load(closure_path)
    special = _load(special_path)
    branch_plan = _load(branch_plan_path)
    dynamic_runtime = _load(dynamic_runtime_path)
    dynamic_body = _load(dynamic_body_path)
    branch_ledger = _load(branch_ledger_path)
    if closure.get("schema") != "uc.controller-closure-state.v1":
        raise ValueError("unsupported controller closure state")
    if special.get("schema") != "uc.ordinary-special-static-closure.v1":
        raise ValueError("unsupported ordinary-special closure")
    if branch_plan.get("schema") != "uc.ability-unobserved-branch-runtime-plan-report.v1":
        raise ValueError("unsupported branch runtime plan report")
    if dynamic_runtime.get("schema") != "uc.ability-dynamic-dispatch-runtime-analysis.v1":
        raise ValueError("unsupported dynamic dispatch analysis")
    if dynamic_body.get("schema") != "uc.ability-dynamic-target-body-ledger.v1":
        raise ValueError("unsupported dynamic target body ledger")
    if branch_ledger.get("schema") != "uc.ability-unobserved-branch-ledger.v1":
        raise ValueError("unsupported unobserved branch ledger")

    offline = {row["claim"]: row for row in closure.get("offline_open", [])}
    runtime = {row["claim"]: row for row in closure.get("runtime_open", [])}
    expected_offline = {
        "retained caller semantic identities outside current static catalogs",
        "Ability executor semantic and external dependency audit",
    }
    expected_runtime = {
        "ordinary special independent runtime coverage",
        "per-move attribution and complete call/return pairing",
    }
    if set(offline) != expected_offline or set(runtime) != expected_runtime:
        raise ValueError("v43 open-item set differs from reviewed boundary input")
    if (len(closure.get("closed_bounded", [])) != 58
            or closure.get("complete_controller") is not False):
        raise ValueError("v43 closure accounting differs")
    if not all(special.get("acceptance", {}).get(key) is True for key in (
            "ordinary_and_enhanced_definitions_present",
            "threshold_parameter_updates_present", "state_attachment_pair_present",
            "controller_state_and_end_state_pair_present", "animation_clip_pair_present",
            "structural_definition_closed")):
        raise ValueError("ordinary/enhanced special structural definition is incomplete")
    if special["acceptance"].get("runtime_execution_required_for_definition_closure") is not False:
        raise ValueError("special closure did not separate definition from execution coverage")
    expected_branch_plan = {
        "logical_source_sites": 14, "physical_predicate_sites": 13,
        "strong_dominating_gate_sites": 10,
        "non_dominating_route_guard_sites": 4,
        "activation_ready": False, "runtime_required_now": True,
    }
    if any(branch_plan.get(key) != value for key, value in expected_branch_plan.items()):
        raise ValueError("branch plan accounting differs")
    dynamic_summary = dynamic_runtime.get("summary", {})
    if (dynamic_summary.get("physical_dynamic_probe_sites") != 35
            or dynamic_summary.get("observed_dynamic_probe_sites") != 20
            or dynamic_summary.get("unobserved_dynamic_probe_sites") != 15):
        raise ValueError("dynamic runtime accounting differs")
    body_summary = dynamic_body.get("summary", {})
    if (body_summary.get("uncatalogued_dynamic_targets") != 5
            or body_summary.get("fully_decoded_bodies") != 5):
        raise ValueError("observed uncatalogued target body accounting differs")
    branch_summary = branch_ledger.get("summary", {})
    if (branch_summary.get("runtime_conditional_sites") != 14
            or branch_summary.get("sites_with_exact_caller_body") != 14
            or branch_summary.get("sites_with_remaining_unresolved_indirect_control") != 0):
        raise ValueError("14-site exact branch frontier differs")

    sources = {
        "controller_closure_v43": _source(closure_path),
        "ordinary_special_static_closure": _source(special_path),
        "branch_input_plan": _source(branch_plan_path),
        "dynamic_dispatch_runtime": _source(dynamic_runtime_path),
        "dynamic_target_body_ledger": _source(dynamic_body_path),
        "unobserved_branch_ledger": _source(branch_ledger_path),
    }
    artifact = {
        "schema": "uc.controller-delivery-boundary.v1",
        "sources": sources,
        "definition": {
            "root": "Remielle Origin authoritative serialized controller/Behavior/Ability graph",
            "include": [
                "serialized nodes, fields, conditions, actions, states and transitions reachable from the Remielle Origin roots",
                "native GameAssembly bodies and exact callsites that schedule or mutate those nodes",
                "runtime-resolved dispatch identities required to replace an otherwise unknown native endpoint",
                "Animator, Wwise, effect and camera dispatch references emitted by in-scope controller nodes",
            ],
            "accepted_native_leaf": (
                "module+rva+code/body boundary+raw ABI or field contract; a human-readable "
                "method name is optional when the original game metadata does not provide one"),
            "exclude_from_recursive_expansion": [
                "allocator, container, loader, generic math and UnityPlayer implementation internals after their exact callsite contract is preserved",
                "semantic renaming of obfuscated methods when native identity and body are already exact",
                "initializer-writer provenance for stable engine slots unless it changes an in-scope control decision",
                "exhaustive player replay of every statically authoritative state or transition",
            ],
        },
        "closed_definition_dimensions": [
            {
                "claim": "ordinary and enhanced special structural definitions",
                "basis": "CurSP threshold rows, Int_BranchIndex writes, attached state pair, controller states and animation clips",
                "runtime_demonstration_required": False,
            },
            {
                "claim": "observed uncatalogued dynamic target native bodies",
                "targets": body_summary["uncatalogued_dynamic_targets"],
                "fully_decoded_bodies": body_summary["fully_decoded_bodies"],
                "human_readable_names_required": False,
            },
            {
                "claim": "unobserved callsite caller control-flow boundaries",
                "sites": branch_summary["runtime_conditional_sites"],
                "exact_caller_bodies": branch_summary["sites_with_exact_caller_body"],
                "remaining_unresolved_indirect_control": 0,
            },
        ],
        "blocking_evidence": [
            {
                "id": "UNOBSERVED_DYNAMIC_ENDPOINT_REALIZATION",
                "logical_sites": 14, "physical_dynamic_sites": 14,
                "reason": (
                    "exact callers and branch frontiers are known, but a complete controller "
                    "still needs either a statically proven receiver/slot endpoint contract or "
                    "an observed runtime endpoint for each in-scope dynamic invocation"),
                "next_offline_action": (
                    "continue receiver provenance from each exact callsite through harvested "
                    "field/materialized types before requesting runtime"),
            },
        ],
        "blocking_delivery_work": [
            {
                "id": "FINAL_NATIVE_CONTROLLER_GRAPH_NOT_ASSEMBLED",
                "reason": (
                    "authoritative components exist, but no single immutable graph package yet "
                    "joins serialized nodes, native bodies, dispatch edges and output channels"),
            },
        ],
        "non_blocking_open_items": [
            {
                "source_claim": "retained caller semantic identities outside current static catalogs",
                "classification": "OPTIONAL_HUMAN_READABLE_LABEL_RECOVERY",
                "count": int(offline[
                    "retained caller semantic identities outside current static catalogs"][
                        "unmatched_rows"]),
            },
            {
                "source_claim": "ordinary special independent runtime coverage",
                "classification": "ENVIRONMENT_CONTINGENT_VALIDATION_ONLY",
                "structural_definition_closed": True,
            },
            {
                "source_claim": "per-move attribution and complete call/return pairing",
                "classification": "VALIDATION_GRANULARITY_NOT_DEFINITION",
                "reason": runtime[
                    "per-move attribution and complete call/return pairing"].get("reason"),
            },
            {
                "source_claim": "18 non-import slot initializer writers",
                "classification": "ENGINE_INFRASTRUCTURE_PROVENANCE",
                "controller_blocking": False,
            },
        ],
        "branch_input_plan_disposition": {
            "status": "DIAGNOSTIC_NOT_SUFFICIENT_AS_STANDALONE",
            "reason": (
                "a pre-branch zero/nonzero value explains path admission, but if the later "
                "callsite remains unexecuted it cannot identify the dynamic callee endpoint"),
            "activate_now": False,
            "reuse": (
                "retain its 13 qualified predicate definitions and merge only surviving points "
                "with receiver/target observations after the static provenance pass"),
        },
        "acceptance": {
            "finite_boundary_frozen": True,
            "controller_complete": False,
            "blocking_evidence_items": 1,
            "blocking_delivery_items": 1,
            "runtime_required_now": False,
            "next_runtime_must_close_a_named_endpoint_gap": True,
        },
        "next_work": [
            "statically trace receiver and record-field provenance for the 14 unobserved dynamic invocation sites",
            "classify exact engine-interface slot leaves separately from truly unknown gameplay-changing endpoints",
            "replace the branch-only activation request with one merged plan only for endpoints that survive static tracing",
            "assemble the final immutable native controller graph after endpoint closure",
        ],
    }
    out.mkdir(parents=True)
    artifact_path = out / "controller-delivery-boundary.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.controller-delivery-boundary-report.v1",
        "artifact": _source(artifact_path),
        "finite_boundary_frozen": True, "controller_complete": False,
        "blocking_evidence_items": 1, "blocking_delivery_items": 1,
        "runtime_required_now": False,
        "branch_input_plan_activate_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--special", type=Path, required=True)
    parser.add_argument("--branch-plan", type=Path, required=True)
    parser.add_argument("--dynamic-runtime", type=Path, required=True)
    parser.add_argument("--dynamic-body", type=Path, required=True)
    parser.add_argument("--branch-ledger", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.closure.resolve(), args.special.resolve(),
                     args.branch_plan.resolve(), args.dynamic_runtime.resolve(),
                     args.dynamic_body.resolve(), args.branch_ledger.resolve(),
                     args.out.resolve())
    except Exception as error:
        write_failure(args.out, "controller_delivery_boundary", error, {
            "closure": str(args.closure), "special": str(args.special),
            "branch_plan": str(args.branch_plan),
            "dynamic_runtime": str(args.dynamic_runtime),
            "dynamic_body": str(args.dynamic_body),
            "branch_ledger": str(args.branch_ledger)})
        raise


if __name__ == "__main__":
    run_main(main)
