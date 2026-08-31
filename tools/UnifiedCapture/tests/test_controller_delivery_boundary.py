from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_delivery_boundary import build


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _inputs(tmp_path: Path) -> tuple[Path, ...]:
    closure = {
        "schema": "uc.controller-closure-state.v1", "complete_controller": False,
        "closed_bounded": [{} for _ in range(58)],
        "offline_open": [
            {"claim": "retained caller semantic identities outside current static catalogs",
             "unmatched_rows": 252},
            {"claim": "Ability executor semantic and external dependency audit"}],
        "runtime_open": [
            {"claim": "ordinary special independent runtime coverage"},
            {"claim": "per-move attribution and complete call/return pairing",
             "reason": "mixed windows"}],
    }
    special = {"schema": "uc.ordinary-special-static-closure.v1", "acceptance": {
        "ordinary_and_enhanced_definitions_present": True,
        "threshold_parameter_updates_present": True,
        "state_attachment_pair_present": True,
        "controller_state_and_end_state_pair_present": True,
        "animation_clip_pair_present": True, "structural_definition_closed": True,
        "runtime_execution_required_for_definition_closure": False,
    }}
    branch_plan = {
        "schema": "uc.ability-unobserved-branch-runtime-plan-report.v1",
        "logical_source_sites": 14, "physical_predicate_sites": 13,
        "strong_dominating_gate_sites": 10,
        "non_dominating_route_guard_sites": 4,
        "activation_ready": False, "runtime_required_now": True,
    }
    dynamic = {"schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
               "summary": {"physical_dynamic_probe_sites": 35,
                           "observed_dynamic_probe_sites": 20,
                           "unobserved_dynamic_probe_sites": 15}}
    body = {"schema": "uc.ability-dynamic-target-body-ledger.v1",
            "summary": {"uncatalogued_dynamic_targets": 5,
                        "fully_decoded_bodies": 5}}
    branch = {"schema": "uc.ability-unobserved-branch-ledger.v1",
              "summary": {"runtime_conditional_sites": 14,
                          "sites_with_exact_caller_body": 14,
                          "sites_with_remaining_unresolved_indirect_control": 0}}
    return tuple(_write(tmp_path / name, value) for name, value in (
        ("closure.json", closure), ("special.json", special),
        ("branch-plan.json", branch_plan), ("dynamic.json", dynamic),
        ("body.json", body), ("branch.json", branch)))


def test_boundary_removes_validation_and_labels_from_blockers(tmp_path: Path) -> None:
    report = build(*_inputs(tmp_path), tmp_path / "out")
    artifact = json.loads(Path(report["artifact"]["path"]).read_text())
    assert report["runtime_required_now"] is False
    assert report["branch_input_plan_activate_now"] is False
    assert artifact["blocking_evidence"][0]["logical_sites"] == 14
    classes = {row["classification"] for row in artifact["non_blocking_open_items"]}
    assert "ENVIRONMENT_CONTINGENT_VALIDATION_ONLY" in classes
    assert "OPTIONAL_HUMAN_READABLE_LABEL_RECOVERY" in classes


def test_boundary_rejects_changed_open_item_set(tmp_path: Path) -> None:
    paths = list(_inputs(tmp_path))
    closure = json.loads(paths[0].read_text())
    closure["runtime_open"].append({"claim": "new gap"})
    paths[0].write_text(json.dumps(closure), encoding="utf-8")
    with __import__("pytest").raises(ValueError, match="open-item set"):
        build(*paths, tmp_path / "out")
