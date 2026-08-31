"""Build the historical rolling controller-evidence ledger.

This pipeline intentionally retains its legacy ``complete_controller=False``
field and must not be used as the terminal completion authority.  Finite
completion is computed by ``controller_completion_contract.py`` from the
immutable native evidence graph.  Keeping the old ledger read-compatible
preserves every prior evidence join without letting its expanding work queue
redefine the frozen controller denominator.
"""
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
        next_plan_path: Path | None = None,
        field_lifecycle_path: Path | None = None,
        field_runtime_join_path: Path | None = None,
        caller_stage_profile_path: Path | None = None,
        caller_static_decode_path: Path | None = None,
        caller_ghidra_join_path: Path | None = None,
        static_gap_analysis_path: Path | None = None,
        runtime_closure_acceptance_path: Path | None = None,
        runtime_closure_caller_join_path: Path | None = None,
        task_context_static_join_path: Path | None = None,
        task_receiver_join_path: Path | None = None,
        task_ancestor_join_path: Path | None = None,
        int_comparison_enum_path: Path | None = None,
        task_reset_audit_path: Path | None = None,
        exact_closure_plan_path: Path | None = None,
        exact_closure_runtime_analysis_path: Path | None = None,
        nested_condition_runtime_analysis_path: Path | None = None,
        selector_join_path: Path | None = None,
        upstream_invoker_join_path: Path | None = None,
        final_runtime_analysis_path: Path | None = None,
        final_identity_join_path: Path | None = None,
        animator_stage_static_join_path: Path | None = None,
        legacy_animator_stage_instance_join_path: Path | None = None,
        ability_executor_coverage_path: Path | None = None,
        action_window_attribution_path: Path | None = None,
        ability_dependency_frontier_path: Path | None = None,
        ability_indirect_call_join_path: Path | None = None,
        ability_external_target_body_ledger_path: Path | None = None,
        ability_external_target_arena_join_path: Path | None = None,
        ability_dynamic_dispatch_plan_path: Path | None = None,
        ability_dynamic_dispatch_runtime_path: Path | None = None,
        ability_dynamic_dispatch_method_join_path: Path | None = None,
        ability_initialized_slot_import_join_path: Path | None = None,
        ability_dynamic_dispatch_authoritative_join_path: Path | None = None,
        ability_initialized_slot_consumer_join_path: Path | None = None,
        ability_dynamic_target_multipass_scan_path: Path | None = None,
        ability_dynamic_target_body_ledger_path: Path | None = None,
        ability_unobserved_static_relevance_path: Path | None = None,
        ability_unobserved_branch_ledger_path: Path | None = None,
        ability_unobserved_predicate_join_path: Path | None = None,
        ability_initialized_slot_module_join_path: Path | None = None,
        ability_initialized_slot_pdata_xrefs_path: Path | None = None,
        ability_initialized_slot_storage_ledger_path: Path | None = None,
        ability_unobserved_base_identity_join_path: Path | None = None,
        ability_unobserved_branch_runtime_plan_path: Path | None = None) -> dict[str, Any]:
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
    field_lifecycle = _load(field_lifecycle_path) if field_lifecycle_path else None
    field_runtime_join = _load(field_runtime_join_path) if field_runtime_join_path else None
    caller_stage_profile = _load(caller_stage_profile_path) if caller_stage_profile_path else None
    caller_static_decode = _load(caller_static_decode_path) if caller_static_decode_path else None
    caller_ghidra_join = _load(caller_ghidra_join_path) if caller_ghidra_join_path else None
    static_gap = _load(static_gap_analysis_path) if static_gap_analysis_path else None
    runtime_closure_acceptance = (_load(runtime_closure_acceptance_path)
                                  if runtime_closure_acceptance_path else None)
    runtime_closure_caller_join = (_load(runtime_closure_caller_join_path)
                                   if runtime_closure_caller_join_path else None)
    task_context_static_join = (_load(task_context_static_join_path)
                                if task_context_static_join_path else None)
    task_receiver_join = _load(task_receiver_join_path) if task_receiver_join_path else None
    task_ancestor_join = _load(task_ancestor_join_path) if task_ancestor_join_path else None
    int_comparison_enum = _load(int_comparison_enum_path) if int_comparison_enum_path else None
    task_reset_audit = _load(task_reset_audit_path) if task_reset_audit_path else None
    exact_closure_plan = _load(exact_closure_plan_path) if exact_closure_plan_path else None
    exact_runtime = (_load(exact_closure_runtime_analysis_path)
                     if exact_closure_runtime_analysis_path else None)
    nested_runtime = (_load(nested_condition_runtime_analysis_path)
                      if nested_condition_runtime_analysis_path else None)
    selector_join = _load(selector_join_path) if selector_join_path else None
    upstream_invoker_join = (_load(upstream_invoker_join_path)
                             if upstream_invoker_join_path else None)
    final_runtime = (_load(final_runtime_analysis_path)
                     if final_runtime_analysis_path else None)
    final_identity = (_load(final_identity_join_path)
                      if final_identity_join_path else None)
    animator_stage_static = (_load(animator_stage_static_join_path)
                             if animator_stage_static_join_path else None)
    legacy_animator_stage = (_load(legacy_animator_stage_instance_join_path)
                             if legacy_animator_stage_instance_join_path else None)
    ability_executor_coverage = (_load(ability_executor_coverage_path)
                                 if ability_executor_coverage_path else None)
    action_window_attribution = (_load(action_window_attribution_path)
                                 if action_window_attribution_path else None)
    ability_dependency_frontier = (_load(ability_dependency_frontier_path)
                                   if ability_dependency_frontier_path else None)
    ability_indirect_call_join = (_load(ability_indirect_call_join_path)
                                  if ability_indirect_call_join_path else None)
    ability_external_target_body_ledger = (
        _load(ability_external_target_body_ledger_path)
        if ability_external_target_body_ledger_path else None)
    ability_external_target_arena_join = (
        _load(ability_external_target_arena_join_path)
        if ability_external_target_arena_join_path else None)
    ability_dynamic_dispatch_plan = (
        _load(ability_dynamic_dispatch_plan_path)
        if ability_dynamic_dispatch_plan_path else None)
    ability_dynamic_dispatch_runtime = (
        _load(ability_dynamic_dispatch_runtime_path)
        if ability_dynamic_dispatch_runtime_path else None)
    ability_dynamic_dispatch_method_join = (
        _load(ability_dynamic_dispatch_method_join_path)
        if ability_dynamic_dispatch_method_join_path else None)
    ability_initialized_slot_import_join = (
        _load(ability_initialized_slot_import_join_path)
        if ability_initialized_slot_import_join_path else None)
    ability_dynamic_dispatch_authoritative_join = (
        _load(ability_dynamic_dispatch_authoritative_join_path)
        if ability_dynamic_dispatch_authoritative_join_path else None)
    ability_initialized_slot_consumer_join = (
        _load(ability_initialized_slot_consumer_join_path)
        if ability_initialized_slot_consumer_join_path else None)
    ability_dynamic_target_multipass_scan = (
        _load(ability_dynamic_target_multipass_scan_path)
        if ability_dynamic_target_multipass_scan_path else None)
    ability_dynamic_target_body_ledger = (
        _load(ability_dynamic_target_body_ledger_path)
        if ability_dynamic_target_body_ledger_path else None)
    ability_unobserved_static_relevance = (
        _load(ability_unobserved_static_relevance_path)
        if ability_unobserved_static_relevance_path else None)
    ability_unobserved_branch_ledger = (
        _load(ability_unobserved_branch_ledger_path)
        if ability_unobserved_branch_ledger_path else None)
    ability_unobserved_predicate_join = (
        _load(ability_unobserved_predicate_join_path)
        if ability_unobserved_predicate_join_path else None)
    ability_initialized_slot_module_join = (
        _load(ability_initialized_slot_module_join_path)
        if ability_initialized_slot_module_join_path else None)
    ability_initialized_slot_pdata_xrefs = (
        _load(ability_initialized_slot_pdata_xrefs_path)
        if ability_initialized_slot_pdata_xrefs_path else None)
    ability_initialized_slot_storage_ledger = (
        _load(ability_initialized_slot_storage_ledger_path)
        if ability_initialized_slot_storage_ledger_path else None)
    ability_unobserved_base_identity_join = (
        _load(ability_unobserved_base_identity_join_path)
        if ability_unobserved_base_identity_join_path else None)
    ability_unobserved_branch_runtime_plan = (
        _load(ability_unobserved_branch_runtime_plan_path)
        if ability_unobserved_branch_runtime_plan_path else None)
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
    if field_lifecycle is not None and field_lifecycle.get("schema") != (
            "uc.controller-field-lifecycle-analysis.v1"):
        raise ValueError("unsupported field lifecycle analysis")
    if field_runtime_join is not None and field_runtime_join.get("schema") != (
            "uc.entry-runtime-static-join.v1"):
        raise ValueError("unsupported field runtime static join")
    if caller_stage_profile is not None and caller_stage_profile.get("schema") != (
            "uc.retained-caller-stage-profile.v1"):
        raise ValueError("unsupported caller stage profile")
    if caller_static_decode is not None and caller_static_decode.get("schema") != (
            "uc.caller-candidate-static-decode.v1"):
        raise ValueError("unsupported caller static decode")
    if caller_ghidra_join is not None and caller_ghidra_join.get("schema") != (
            "uc.caller-candidate-ghidra-join.v1"):
        raise ValueError("unsupported caller Ghidra join")
    if static_gap is not None and static_gap.get("schema") != (
            "uc.controller-static-gap-analysis.v1"):
        raise ValueError("unsupported controller static gap analysis")
    closure_inputs = (runtime_closure_acceptance, runtime_closure_caller_join,
                      task_context_static_join)
    if any(row is not None for row in closure_inputs) and not all(
            row is not None for row in closure_inputs):
        raise ValueError("runtime closure consolidation requires acceptance, caller join, and task context join")
    if runtime_closure_acceptance is not None:
        if runtime_closure_acceptance.get("schema") not in (
                "uc.entry-evidence-acceptance.v1", "uc.entry-evidence-acceptance.v2"):
            raise ValueError("unsupported runtime closure acceptance")
        if not runtime_closure_acceptance.get("accepted") or not (
                runtime_closure_acceptance.get("game_runtime_verified")):
            raise ValueError("runtime closure session is not accepted game evidence")
        if any(row.get("status", "").startswith("UNKNOWN")
               for row in runtime_closure_acceptance.get("points", [])):
            raise ValueError("runtime closure acceptance contains unknown points")
        if runtime_closure_caller_join.get("schema") != "uc.controller-runtime-caller-join.v1":
            raise ValueError("unsupported runtime closure caller join")
        if task_context_static_join.get("schema") != "uc.task-context-static-join.v1":
            raise ValueError("unsupported task context static join")
    if task_receiver_join is not None:
        if runtime_closure_acceptance is None:
            raise ValueError("task receiver join requires runtime closure evidence")
        if task_receiver_join.get("schema") != "uc.task-receiver-runtime-join.v1":
            raise ValueError("unsupported task receiver runtime join")
    if task_ancestor_join is not None:
        if task_context_static_join is None or runtime_closure_acceptance is None:
            raise ValueError("task ancestor join requires runtime task context evidence")
        if task_ancestor_join.get("schema") != "uc.task-ancestor-static-join.v1":
            raise ValueError("unsupported task ancestor static join")
    if int_comparison_enum is not None:
        if task_ancestor_join is None:
            raise ValueError("IntComparison enum decode requires task ancestor evidence")
        if int_comparison_enum.get("schema") != "uc.int-comparison-enum-decode.v1":
            raise ValueError("unsupported IntComparison enum decode")
    if task_reset_audit is not None:
        if task_reset_audit.get("schema") != "uc.task-reset-dispatch-audit.v1":
            raise ValueError("unsupported task reset dispatch audit")
    if exact_closure_plan is not None:
        if exact_closure_plan.get("schema") != "uc.capture-plan.v1":
            raise ValueError("unsupported exact closure plan")
    if final_identity is not None:
        if final_runtime is None:
            raise ValueError("final identity join requires final runtime analysis")
        if final_identity.get("schema") != "uc.controller-final-identity-join.v1":
            raise ValueError("unsupported final identity join")
        checks = final_identity.get("checks", {})
        if not checks or not all(checks.values()):
            raise ValueError("final identity join is incomplete")
        if (final_identity.get("session_id") != final_runtime.get("session_id")
                or final_identity.get("generation") != final_runtime.get("generation")):
            raise ValueError("final identity and runtime analysis differ by session or generation")
    if animator_stage_static is not None:
        if animator_stage_static.get("schema") != "uc.animator-stage-receiver-static-join.v1":
            raise ValueError("unsupported Animator stage static join")
        required_witnesses = {
            "animator_to_consumer", "consumer_callback_to_evaluator",
            "evaluator_to_machine", "machine_to_stage_cd4c80",
            "machine_to_stage_cd9640",
        }
        if set(animator_stage_static.get("witnesses", {})) != required_witnesses:
            raise ValueError("Animator stage static ownership path is incomplete")
    if legacy_animator_stage is not None:
        if legacy_animator_stage.get("schema") != (
                "uc.legacy-animator-stage-instance-join.v1"):
            raise ValueError("unsupported legacy Animator stage instance join")
        checks = legacy_animator_stage.get("checks", {})
        if not checks or not all(checks.values()):
            raise ValueError("legacy Animator stage instance join is incomplete")
    if ability_executor_coverage is not None:
        if ability_executor_coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
            raise ValueError("unsupported Ability executor coverage ledger")
        coverage_summary = ability_executor_coverage.get("summary", {})
        if (coverage_summary.get("types") != 188
                or coverage_summary.get("positions_complete_types") != 188
                or coverage_summary.get("exact_pdata_entries") !=
                coverage_summary.get("fully_decoded_pdata_bodies")):
            raise ValueError("Ability executor coverage ledger is incomplete or inconsistent")
    if action_window_attribution is not None:
        if final_identity is None or final_runtime is None:
            raise ValueError("action-window attribution requires final runtime identity evidence")
        if action_window_attribution.get("schema") != "uc.action-window-receiver-attribution.v1":
            raise ValueError("unsupported action-window receiver attribution")
        if (action_window_attribution.get("session_id") != final_runtime.get("session_id")
                or action_window_attribution.get("generation") != final_runtime.get("generation")):
            raise ValueError("action-window attribution differs from final runtime session")
        attribution_summary = action_window_attribution.get("summary", {})
    if ability_dependency_frontier is not None:
        if ability_executor_coverage is None:
            raise ValueError("Ability dependency frontier requires executor coverage")
        if ability_dependency_frontier.get("schema") != "uc.ability-executor-dependency-frontier.v1":
            raise ValueError("unsupported Ability dependency frontier")
        if ability_dependency_frontier.get("summary", {}).get("indirect_callsites") != 353:
            raise ValueError("Ability dependency frontier is not the bounded 353-callsite set")
    if ability_indirect_call_join is not None:
        if ability_dependency_frontier is None:
            raise ValueError("Ability indirect call join requires dependency frontier")
        if ability_indirect_call_join.get("schema") != "uc.ability-executor-indirect-call-join.v1":
            raise ValueError("unsupported Ability indirect call join")
        indirect_summary = ability_indirect_call_join.get("summary", {})
        if indirect_summary.get("indirect_callsites") != 353:
            raise ValueError("Ability indirect call join is not the bounded 353-callsite set")
        resolved = (indirect_summary.get("exact_semantic_wrapper_callsites", 0)
                    + indirect_summary.get("exact_static_target_without_semantic_identity_callsites", 0)
                    + indirect_summary.get("remaining_without_exact_target_identity", 0))
        if resolved != 353:
            raise ValueError("Ability indirect call join accounting is incomplete")
        if (attribution_summary.get("windows") != 33
                or attribution_summary.get("complete_lossless_windows") != 33):
            raise ValueError("action-window attribution lacks 33 complete lossless windows")
    if ability_external_target_body_ledger is not None:
        if ability_dependency_frontier is None:
            raise ValueError("Ability external body ledger requires dependency frontier")
        if ability_external_target_body_ledger.get("schema") != (
                "uc.ability-external-target-body-ledger.v1"):
            raise ValueError("unsupported Ability external target body ledger")
        body_summary = ability_external_target_body_ledger.get("summary", {})
        dependency_summary = ability_dependency_frontier.get("summary", {})
        if (body_summary.get("targets") !=
                dependency_summary.get("unique_external_direct_targets")
                or body_summary.get("exact_pdata_bodies") != 705
                or body_summary.get("unidentified_targets") !=
                dependency_summary.get("unique_external_direct_targets")
                - dependency_summary.get("source_identified_or_annotated_targets")):
            raise ValueError("Ability external target body ledger accounting is incomplete")
    if ability_external_target_arena_join is not None:
        if ability_external_target_body_ledger is None:
            raise ValueError("Ability external target arena join requires external body ledger")
        if ability_external_target_arena_join.get("schema") != (
                "uc.ability-external-target-arena-join.v1"):
            raise ValueError("unsupported Ability external target arena join")
        arena_summary = ability_external_target_arena_join.get("summary", {})
        body_summary = ability_external_target_body_ledger.get("summary", {})
        expected = (body_summary.get("unidentified_targets", 0)
                    - body_summary.get("body_class_counts", {}).get(
                        "NO_EXACT_PDATA_ENTRY", 0))
        if (arena_summary.get("requested_unidentified_exact_pdata_targets") != expected
                or arena_summary.get("targets_with_arena_method_candidate", 0)
                + arena_summary.get("targets_not_present_in_preserved_arena", 0) != expected):
            raise ValueError("Ability external target arena join accounting is incomplete")
    if ability_dynamic_dispatch_plan is not None:
        if ability_external_target_arena_join is None:
            raise ValueError("Ability dynamic dispatch plan requires external target arena join")
        if ability_dynamic_dispatch_plan.get("schema") != (
                "uc.ability-dynamic-dispatch-plan-report.v1"):
            raise ValueError("unsupported Ability dynamic dispatch plan report")
        required_counts = {
            "unresolved_initialized_slots": 21,
            "dynamic_callsites": 36,
            "physical_dynamic_probe_sites": 35,
            "coalesced_adjacent_callsites": 1,
            "qualification_sites": 36,
            "near_only_qualification_sites": 10,
            "direct_relocation_interior_edges": 0,
        }
        if any(ability_dynamic_dispatch_plan.get(key) != value
               for key, value in required_counts.items()):
            raise ValueError("Ability dynamic dispatch plan does not cover the bounded gap set")
        if (ability_dynamic_dispatch_plan.get("activation_ready") is not False
                or ability_dynamic_dispatch_plan.get("runtime_required_now") is not True):
            raise ValueError("Ability dynamic dispatch plan activation state is invalid")
    dynamic_runtime_inputs = (
        ability_dynamic_dispatch_runtime,
        ability_dynamic_dispatch_method_join,
        ability_initialized_slot_import_join,
    )
    if any(row is not None for row in dynamic_runtime_inputs) and not all(
            row is not None for row in dynamic_runtime_inputs):
        raise ValueError(
            "Ability dynamic dispatch consolidation requires runtime, method join, and slot import join")
    if ability_dynamic_dispatch_runtime is not None:
        if ability_dynamic_dispatch_plan is None:
            raise ValueError("Ability dynamic dispatch runtime requires its source plan report")
        if ability_dynamic_dispatch_runtime.get("schema") != (
                "uc.ability-dynamic-dispatch-runtime-analysis.v1"):
            raise ValueError("unsupported Ability dynamic dispatch runtime analysis")
        runtime_summary = ability_dynamic_dispatch_runtime.get("summary", {})
        expected_runtime = {
            "initialized_slots_expected": 21,
            "initialized_slots_observed": 21,
            "initialized_slots_stable": 21,
            "logical_dynamic_callsites": 36,
            "physical_dynamic_probe_sites": 35,
            "observed_dynamic_probe_sites": 20,
            "unobserved_dynamic_probe_sites": 15,
            "semantic_callee_names_assigned": 0,
        }
        if any(runtime_summary.get(key) != value
               for key, value in expected_runtime.items()):
            raise ValueError("Ability dynamic dispatch runtime accounting is incomplete")
        runtime_session = ability_dynamic_dispatch_runtime.get("session", {})
        if (runtime_session.get("cleanup") != "STOPPED_CLEAN"
                or runtime_session.get("storage_complete") is not True
                or runtime_session.get("loss_events") != 0
                or runtime_session.get("coverage_complete_points") != 36
                or runtime_session.get("event_count") != 28992):
            raise ValueError("Ability dynamic dispatch runtime session is not clean and complete")
        static_contract_source = ability_dynamic_dispatch_runtime.get(
            "sources", {}).get("static_contract", {})
        if static_contract_source.get("sha256") != ability_dynamic_dispatch_plan.get(
                "static_contract", {}).get("sha256"):
            raise ValueError("Ability dynamic dispatch runtime and plan static contracts differ")
        runtime_hash = file_hash(ability_dynamic_dispatch_runtime_path)
        if ability_dynamic_dispatch_method_join.get("schema") != (
                "uc.ability-dynamic-dispatch-method-join.v1"):
            raise ValueError("unsupported Ability dynamic dispatch method join")
        method_summary = ability_dynamic_dispatch_method_join.get("summary", {})
        if method_summary != {
                "observed_game_target_rvas": 18,
                "exact_catalogued_method_targets": 9,
                "uncatalogued_method_targets": 9,
                "observed_class_target_pairs": 17}:
            raise ValueError("Ability dynamic dispatch method join accounting is incomplete")
        if ability_dynamic_dispatch_method_join.get("sources", {}).get(
                "runtime_analysis", {}).get("sha256") != runtime_hash:
            raise ValueError("Ability dynamic dispatch method join has a different runtime source")
        if ability_initialized_slot_import_join.get("schema") != (
                "uc.ability-initialized-slot-import-join.v1"):
            raise ValueError("unsupported Ability initialized-slot import join")
        slot_summary = ability_initialized_slot_import_join.get("summary", {})
        if slot_summary != {
                "initialized_slots": 21,
                "pe_import_slots": 3,
                "non_import_initialized_slots": 18}:
            raise ValueError("Ability initialized-slot import accounting is incomplete")
        if ability_initialized_slot_import_join.get("sources", {}).get(
                "runtime_analysis", {}).get("sha256") != runtime_hash:
            raise ValueError("Ability initialized-slot import join has a different runtime source")
    dynamic_offline_inputs = (
        ability_dynamic_dispatch_authoritative_join,
        ability_initialized_slot_consumer_join,
        ability_dynamic_target_multipass_scan,
        ability_dynamic_target_body_ledger,
        ability_unobserved_static_relevance,
    )
    if any(row is not None for row in dynamic_offline_inputs) and not all(
            row is not None for row in dynamic_offline_inputs):
        raise ValueError("Ability post-runtime offline consolidation requires all five evidence joins")
    if ability_dynamic_dispatch_authoritative_join is not None:
        if ability_dynamic_dispatch_runtime is None:
            raise ValueError("Ability post-runtime offline evidence requires runtime consolidation")
        if ability_dynamic_dispatch_authoritative_join.get("schema") != (
                "uc.ability-dynamic-dispatch-authoritative-method-join.v1"):
            raise ValueError("unsupported authoritative dynamic method join")
        authoritative_summary = ability_dynamic_dispatch_authoritative_join.get("summary", {})
        if authoritative_summary != {
                "base_exact_catalogued_method_targets": 9,
                "exact_catalogued_method_targets": 13,
                "newly_catalogued_method_targets": 4,
                "observed_class_target_pairs": 17,
                "observed_game_target_rvas": 18,
                "uncatalogued_method_targets": 5}:
            raise ValueError("authoritative dynamic method accounting is incomplete")
        if ability_dynamic_dispatch_authoritative_join.get("sources", {}).get(
                "base_method_join", {}).get("sha256") != file_hash(
                    ability_dynamic_dispatch_method_join_path):
            raise ValueError("authoritative method join does not bind the base method join")
        if ability_initialized_slot_consumer_join.get("schema") != (
                "uc.ability-initialized-slot-consumer-join.v1"):
            raise ValueError("unsupported initialized-slot consumer join")
        consumer_summary = ability_initialized_slot_consumer_join.get("summary", {})
        if consumer_summary != {
                "initialized_slots": 21, "non_import_slots": 18,
                "non_import_slots_with_static_consumers": 18,
                "non_import_slots_with_unresolved_initializer": 18,
                "pe_import_slots": 3, "slots_with_static_consumers": 21,
                "static_consumer_callsites": 58}:
            raise ValueError("initialized-slot consumer accounting is incomplete")
        if ability_initialized_slot_consumer_join.get("sources", {}).get(
                "initialized_slot_import_join", {}).get("sha256") != file_hash(
                    ability_initialized_slot_import_join_path):
            raise ValueError("slot consumer join does not bind the import join")
        if ability_dynamic_target_multipass_scan.get("schema") != (
                "uc.ability-private-load-multipass-scan.v1"):
            raise ValueError("unsupported dynamic target multipass scan")
        scan_summary = ability_dynamic_target_multipass_scan.get("summary", {})
        if scan_summary != {
                "target_rvas": 5, "requested_types": 9121, "covered_types": 9121,
                "uncovered_types": 0, "exact_positive_matches": 0,
                "scan_complete": True}:
            raise ValueError("dynamic target multipass scan is not a complete bounded negative")
        if ability_dynamic_target_body_ledger.get("schema") != (
                "uc.ability-dynamic-target-body-ledger.v1"):
            raise ValueError("unsupported dynamic target body ledger")
        body_summary = ability_dynamic_target_body_ledger.get("summary", {})
        if body_summary != {
                "uncatalogued_dynamic_targets": 5, "exact_pdata_bodies": 5,
                "fully_decoded_bodies": 5,
                "complete_private_load_owner_scan_types": 9121,
                "private_load_exact_owner_matches": 0,
                "exact_fast_path_field_loads": 2}:
            raise ValueError("dynamic target body ledger accounting is incomplete")
        if (ability_dynamic_target_body_ledger.get("sources", {}).get(
                "authoritative_method_join", {}).get("sha256") != file_hash(
                    ability_dynamic_dispatch_authoritative_join_path)
                or ability_dynamic_target_body_ledger.get("sources", {}).get(
                    "multipass_owner_scan", {}).get("sha256") != file_hash(
                        ability_dynamic_target_multipass_scan_path)):
            raise ValueError("dynamic target body ledger source chain differs")
        if ability_unobserved_static_relevance.get("schema") != (
                "uc.ability-unobserved-static-relevance.v1"):
            raise ValueError("unsupported unobserved-site static relevance")
        relevance_summary = ability_unobserved_static_relevance.get("summary", {})
        if relevance_summary != {
                "unobserved_physical_probe_sites": 15,
                "represented_unobserved_callsites": 15,
                "callsites_with_remielle_origin_asset_occurrences": 15,
                "unique_caller_types": 8,
                "classification_counts": {
                    "RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH": 14,
                    "STATIC_INITIALIZER_TIMING_SITE": 1}}:
            raise ValueError("unobserved-site static relevance accounting is incomplete")
        if ability_unobserved_static_relevance.get("sources", {}).get(
                "runtime_analysis", {}).get("sha256") != file_hash(
                    ability_dynamic_dispatch_runtime_path):
            raise ValueError("unobserved-site relevance does not bind runtime analysis")

    dynamic_branch_and_slot_inputs = (
        ability_unobserved_branch_ledger,
        ability_unobserved_predicate_join,
        ability_initialized_slot_module_join,
        ability_initialized_slot_pdata_xrefs,
        ability_initialized_slot_storage_ledger,
    )
    if any(row is not None for row in dynamic_branch_and_slot_inputs) and not all(
            row is not None for row in dynamic_branch_and_slot_inputs):
        raise ValueError("Ability branch/slot consolidation requires all five evidence ledgers")
    if ability_unobserved_branch_ledger is not None:
        if ability_dynamic_dispatch_authoritative_join is None:
            raise ValueError("Ability branch/slot evidence requires post-runtime offline joins")
        if ability_unobserved_branch_ledger.get("schema") != (
                "uc.ability-unobserved-branch-ledger.v1"):
            raise ValueError("unsupported unobserved branch ledger")
        branch_summary = ability_unobserved_branch_ledger.get("summary", {})
        if branch_summary != {
                "runtime_conditional_sites": 14,
                "semantic_predicates_assigned": 0,
                "sites_mandatory_in_complete_mechanical_cfg": 0,
                "sites_not_reached_by_current_mechanical_cfg": 0,
                "sites_reachable_but_not_mandatory_in_complete_mechanical_cfg": 14,
                "sites_reachable_in_current_mechanical_cfg": 14,
                "sites_with_exact_caller_body": 14,
                "sites_with_mechanical_gating_branch": 10,
                "sites_with_outcome_sensitive_branch": 14,
                "sites_with_remaining_unresolved_indirect_control": 0,
                "total_mechanical_gating_branches": 48,
                "total_outcome_sensitive_branches": 183}:
            raise ValueError("unobserved branch accounting is incomplete")
        if ability_unobserved_branch_ledger.get("sources", {}).get(
                "static_relevance", {}).get("sha256") != file_hash(
                    ability_unobserved_static_relevance_path):
            raise ValueError("unobserved branch ledger does not bind static relevance")
        if ability_unobserved_predicate_join.get("schema") != (
                "uc.ability-unobserved-predicate-join.v1"):
            raise ValueError("unsupported unobserved predicate join")
        predicate_summary = ability_unobserved_predicate_join.get("summary", {})
        if predicate_summary != {
                "exact_field_identities_assigned": 0,
                "predicate_shape_counts": {"MEMORY_COMPARE": 1,
                                           "REGISTER_ZERO_TEST": 9,
                                           "RIP_RELATIVE_MEMORY_COMPARE_ZERO": 4},
                "selection_counts": {
                    "NEAREST_PRECEDING_NON_DOMINATING_OUTCOME_SENSITIVE_BRANCH": 4,
                    "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE": 10},
                "semantic_gameplay_predicates_assigned": 0,
                "sites": 14,
                "sites_with_harvested_field_offset_candidates": 7}:
            raise ValueError("unobserved predicate accounting is incomplete")
        if ability_unobserved_predicate_join.get("sources", {}).get(
                "branch_ledger", {}).get("sha256") != file_hash(
                    ability_unobserved_branch_ledger_path):
            raise ValueError("predicate join does not bind branch ledger")
        if ability_initialized_slot_module_join.get("schema") != (
                "uc.ability-initialized-slot-module-join.v1"):
            raise ValueError("unsupported initialized-slot module join")
        module_summary = ability_initialized_slot_module_join.get("summary", {})
        if module_summary != {
                "candidate_modules_scanned": 17, "initializer_write_sites_resolved": 0,
                "non_import_slots": 18, "selected_module": "UnityPlayer.dll",
                "selected_runtime_base": 140717056131072,
                "slots_with_exact_module_pdata_target": 18,
                "unique_exact_module_pdata_targets": 17,
                "unique_full_exact_module_base_matches": 1,
                "unique_runtime_targets": 17}:
            raise ValueError("initialized-slot module accounting is incomplete")
        consumer_hash = file_hash(ability_initialized_slot_consumer_join_path)
        if ability_initialized_slot_module_join.get("sources", {}).get(
                "consumer_join", {}).get("sha256") != consumer_hash:
            raise ValueError("slot module join does not bind consumer join")
        if ability_initialized_slot_pdata_xrefs.get("schema") != (
                "uc.ability-initialized-slot-pdata-xrefs.v1"):
            raise ValueError("unsupported initialized-slot PDATA xrefs")
        xref_summary = ability_initialized_slot_pdata_xrefs.get("summary", {})
        if xref_summary != {
                "access_counts": {"READ": 3894}, "exact_rip_relative_references": 3894,
                "fully_linearly_decoded_pdata_records": 1355043,
                "incompletely_linearly_decoded_pdata_records": 322,
                "non_import_slots": 18, "pdata_records": 1355365,
                "referenced_slots": 18, "slots_with_pdata_write_reference": 0,
                "slots_without_pdata_write_reference": 18}:
            raise ValueError("initialized-slot PDATA xref accounting is incomplete")
        if ability_initialized_slot_pdata_xrefs.get("sources", {}).get(
                "consumer_join", {}).get("sha256") != consumer_hash:
            raise ValueError("slot PDATA xrefs do not bind consumer join")
        if ability_initialized_slot_storage_ledger.get("schema") != (
                "uc.ability-initialized-slot-storage-ledger.v1"):
            raise ValueError("unsupported initialized-slot storage ledger")
        storage_summary = ability_initialized_slot_storage_ledger.get("summary", {})
        if storage_summary != {
                "initializer_write_sites_resolved": 0, "slots": 18,
                "slots_in_data_section": 18,
                "slots_with_exact_runtime_target_module_rva": 18,
                "slots_without_decoded_gameassembly_pdata_write_reference": 18,
                "slots_without_file_backed_initial_value": 18,
                "storage_counts": {"VIRTUAL_ZERO_FILL_TAIL": 18}}:
            raise ValueError("initialized-slot storage accounting is incomplete")
        storage_sources = ability_initialized_slot_storage_ledger.get("sources", {})
        if (storage_sources.get("module_join", {}).get("sha256") != file_hash(
                ability_initialized_slot_module_join_path)
                or storage_sources.get("pdata_xrefs", {}).get("sha256") != file_hash(
                    ability_initialized_slot_pdata_xrefs_path)):
            raise ValueError("slot storage ledger source chain differs")
    if ability_unobserved_base_identity_join is not None:
        if ability_unobserved_branch_ledger is None:
            raise ValueError("Ability base-identity evidence requires branch/slot consolidation")
        if ability_unobserved_base_identity_join.get("schema") != (
                "uc.ability-unobserved-base-identity-join.v1"):
            raise ValueError("unsupported unobserved base-identity join")
        base_summary = ability_unobserved_base_identity_join.get("summary", {})
        if base_summary != {
                "sites": 14, "sites_with_stable_nonvolatile_this_alias": 12,
                "sites_with_exact_field_access_in_selected_window": 5,
                "selected_test_values_with_exact_object_provenance": 2,
                "semantic_gameplay_predicates_assigned": 0}:
            raise ValueError("unobserved base-identity accounting is incomplete")
        if ability_unobserved_base_identity_join.get("sources", {}).get(
                "predicate_join", {}).get("sha256") != file_hash(
                    ability_unobserved_predicate_join_path):
            raise ValueError("base-identity join does not bind predicate join")
    if ability_unobserved_branch_runtime_plan is not None:
        if ability_unobserved_base_identity_join is None:
            raise ValueError("Ability branch runtime plan requires base-identity evidence")
        if ability_unobserved_branch_runtime_plan.get("schema") != (
                "uc.ability-unobserved-branch-runtime-plan-report.v1"):
            raise ValueError("unsupported Ability branch runtime plan report")
        plan_summary = ability_unobserved_branch_runtime_plan
        expected_plan_summary = {
            "logical_source_sites": 14, "physical_predicate_sites": 13,
            "coalesced_logical_sites": 1, "strong_dominating_gate_sites": 10,
            "non_dominating_route_guard_sites": 4,
            "exact_tested_object_controls": 2, "qualification_sites": 13,
            "near_only_sites": 13, "activation_ready": False,
            "runtime_required_now": True,
        }
        if any(plan_summary.get(key) != value
               for key, value in expected_plan_summary.items()):
            raise ValueError("Ability branch runtime plan accounting differs")

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
                ("all points are definitive and the sealed run is globally accepted"
                 if frontier.get("accepted") and not unknown else
                 f"all points must be definitive; {len(unknown)} lossy points keep global acceptance false"),
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
    if ability_dynamic_dispatch_runtime is not None:
        runtime_summary = ability_dynamic_dispatch_runtime["summary"]
        runtime_session = ability_dynamic_dispatch_runtime["session"]
        method_summary = ability_dynamic_dispatch_method_join["summary"]
        slot_summary = ability_initialized_slot_import_join["summary"]
        result["sources"].update({
            "ability_dynamic_dispatch_plan": _source(
                ability_dynamic_dispatch_plan_path),
            "ability_dynamic_dispatch_runtime": _source(
                ability_dynamic_dispatch_runtime_path),
            "ability_dynamic_dispatch_method_join": _source(
                ability_dynamic_dispatch_method_join_path),
            "ability_initialized_slot_import_join": _source(
                ability_initialized_slot_import_join_path),
        })
        result["closed_bounded"].extend([
            {
                "claim": "Ability initialized target slots observed stable in one clean generation",
                "initialized_slots": runtime_summary["initialized_slots_observed"],
                "stable_slots": runtime_summary["initialized_slots_stable"],
                "pe_import_slots": slot_summary["pe_import_slots"],
                "non_import_initialized_slots": slot_summary[
                    "non_import_initialized_slots"],
                "scope": ("exact slot RVAs and same-generation captured pointer values; only "
                          "exact PE import-table matches receive import identities"),
            },
            {
                "claim": "Ability dynamic dispatch targets observed in complete covered session",
                "logical_dynamic_callsites": runtime_summary[
                    "logical_dynamic_callsites"],
                "physical_dynamic_probe_sites": runtime_summary[
                    "physical_dynamic_probe_sites"],
                "observed_dynamic_probe_sites": runtime_summary[
                    "observed_dynamic_probe_sites"],
                "unobserved_dynamic_probe_sites": runtime_summary[
                    "unobserved_dynamic_probe_sites"],
                "observed_game_target_rvas": method_summary[
                    "observed_game_target_rvas"],
                "observed_class_target_pairs": method_summary[
                    "observed_class_target_pairs"],
                "exact_catalogued_method_targets": method_summary[
                    "exact_catalogued_method_targets"],
                "uncatalogued_method_targets": method_summary[
                    "uncatalogued_method_targets"],
                "scope": ("one lossless clean generation; unexecuted sites remain "
                          "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION and no semantic name is guessed"),
            },
            {
                "claim": "Ability dynamic-dispatch evidence integrity",
                "event_count": runtime_session["event_count"],
                "coverage_complete_points": runtime_session[
                    "coverage_complete_points"],
                "loss_events": runtime_session["loss_events"],
                "cleanup": runtime_session["cleanup"],
                "storage_complete": runtime_session["storage_complete"],
            },
        ])
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "runtime_observed_dynamic_targets": method_summary[
                        "observed_game_target_rvas"],
                    "runtime_targets_with_exact_catalog_method": method_summary[
                        "exact_catalogued_method_targets"],
                    "runtime_targets_without_catalog_method": method_summary[
                        "uncatalogued_method_targets"],
                    "non_import_initialized_slots_without_owner": slot_summary[
                        "non_import_initialized_slots"],
                    "dynamic_probe_sites_not_observed": runtime_summary[
                        "unobserved_dynamic_probe_sites"],
                })
                row["reason"] = (
                    "the clean runtime generation supplies exact values for all initialized "
                    "slots and exact receiver/class/target evidence for 20 physical dynamic "
                    "sites; remaining work is bounded static ownership and method-catalog "
                    "recovery, plus static relevance analysis of 15 unobserved sites")
        result.pop("next_capture", None)
        result["next_work"] = [
            "map the 9 uncatalogued observed GameAssembly target RVAs using authoritative method/type and native-body evidence",
            "resolve the 18 non-PE-import initialized slot owners from static registration and preserved arena evidence without guessing a module",
            "statically assess the 15 unobserved dynamic sites for Remielle relevance before proposing any further runtime capture",
        ]
        result["runtime_required_now"] = False
    # Runtime results supersede the earlier prepared-plan state.  Keep this
    # final projection after every optional evidence layer so later static
    # consolidators cannot accidentally resurrect a completed capture unit.
    if exact_runtime is not None:
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = ("the five authoritative Remielle condition signatures and their "
                                 "ConditionalEvaluator task-owner relations are now observed; selector "
                                 "choice and other asynchronous queue edges remain open")
            elif row["claim"] == "native object lifecycle to Remielle entity identity":
                row["reason"] = ("load/destroy boundaries and the five-condition owner establish "
                                 "ObjectCandidates, but no native creation generation or Remielle "
                                 "EntityIdentity binding has been observed")
        result.pop("next_capture", None)
        result["next_work"] = [
            "merge the same-session five-condition owner relation into the native controller execution graph",
            "statically narrow selector choice and the upstream selected Unity API target to invoker edge before designing another runtime unit",
            "retain ordinary special independent coverage and per-move attribution as explicit gaps; do not repeat broad gameplay capture",
        ]
        result["runtime_required_now"] = False
    runtime_result_inputs = (exact_runtime, nested_runtime)
    if any(row is not None for row in runtime_result_inputs) and not all(
            row is not None for row in runtime_result_inputs):
        raise ValueError("exact closure consolidation requires both runtime analyses")
    if exact_runtime is not None:
        if exact_runtime.get("schema") != "uc.controller-exact-closure-runtime-analysis.v1":
            raise ValueError("unsupported exact closure runtime analysis")
        if nested_runtime.get("schema") != "uc.controller-nested-condition-runtime-analysis.v1":
            raise ValueError("unsupported nested condition runtime analysis")
        if not exact_runtime.get("checks", {}).get("entry_session_accepted") or not (
                exact_runtime.get("checks", {}).get("store_clean")):
            raise ValueError("exact closure runtime analysis is not accepted clean evidence")
        conditions = nested_runtime.get("conditions", {})
        if conditions.get("status") != "OBSERVED_EXPECTED_CONDITION_SET" or \
                conditions.get("matching_signature_count") != 5:
            raise ValueError("nested runtime did not observe the authoritative five-condition set")
        relations = nested_runtime.get("object_relations", {})
        if not relations.get("conditional_evaluator_to_task_consistent") or not (
                relations.get("task_to_owner_consistent")):
            raise ValueError("nested runtime object relations are inconsistent")
        if len(relations.get("matching_condition_owners", [])) != 1:
            raise ValueError("five-condition set does not resolve to one runtime owner candidate")
        result["sources"]["controller_exact_closure_runtime_analysis"] = _source(
            exact_closure_runtime_analysis_path)
        result["sources"]["controller_nested_condition_runtime_analysis"] = _source(
            nested_condition_runtime_analysis_path)
        result["closed_bounded"].extend([
            {"claim": "Remielle five serialized condition signatures runtime execution",
             "evidence": "same-session exact-promoted IntComparison records",
             "conditions": conditions["expected_static"],
             "scope": "Int_AIMoveType == 1/2 and Int_ActiveSkill == 1/2/5"},
            {"claim": "ConditionalEvaluator task-owner runtime object relations",
             "evidence": "entry-register and source-verified field reads",
             "matching_condition_owners": relations.get("matching_condition_owners", []),
             "all_observed_owners": relations.get("owners", []),
             "identity_level": relations.get("identity_level")},
        ])
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = ("the five authoritative Remielle condition signatures and their "
                                 "ConditionalEvaluator task-owner relations are now observed; selector "
                                 "choice and other asynchronous queue edges remain open")
            elif row["claim"] == "native object lifecycle to Remielle entity identity":
                row["reason"] = ("load/destroy boundaries and the five-condition owner establish "
                                 "ObjectCandidates, but no native creation generation or Remielle "
                                 "EntityIdentity binding has been observed")
        result.pop("next_capture", None)
        result["next_work"] = [
            "merge the same-session five-condition owner relation into the native controller execution graph",
            "statically narrow selector choice and the upstream selected Unity API target to invoker edge before designing another runtime unit",
            "retain ordinary special independent coverage and per-move attribution as explicit gaps; do not repeat broad gameplay capture",
        ]
        result["runtime_required_now"] = False
    if field_lifecycle is not None:
        if frontier is None or not frontier.get("accepted"):
            raise ValueError("field lifecycle analysis requires an accepted causal frontier")
        result["sources"]["field_lifecycle_analysis"] = _source(field_lifecycle_path)
        field_summary = field_lifecycle["summary"]
        result["closed_bounded"].extend([
            {
                "claim": "same-address parameter task phase coverage",
                "start_and_update_candidates":
                    field_summary["parameter_task_start_update_same_address"],
                "address_candidates": field_summary["parameter_task_address_candidates"],
                "reset_observed_candidates": field_summary["parameter_task_reset_observed"],
                "scope": "ObservedAddress layer in lossless checkpoint interiors; no entity upgrade",
            },
            {
                "claim": "ECS system address lifecycle coverage",
                "complete_lifecycles": field_summary["ecs_complete_lifecycles"],
                "address_candidates": field_summary["ecs_system_address_candidates"],
                "open_end_boundaries": field_summary["ecs_open_end_boundary"],
                "scope": "same raw RCX across native lifecycle callbacks",
            },
        ])
        bridge = next((row for row in frontier.get("points", [])
                       if row.get("point", "").startswith(
                           "GameAssembly.animator-fixed-update-bridge@")
                       and row.get("status") == "OBSERVED"), None)
        if bridge is not None:
            result["closed_bounded"].append({
                "claim": "live selected Animator fixed-update bridge code entry",
                "event_count": bridge.get("event_count", 0),
                "scope": "accepted current-process generation; entry execution only",
            })
            result["runtime_open"] = [row for row in result["runtime_open"]
                                      if row["claim"] !=
                                      "live selected Unity bridge invocation for the current game instance"]
            result["runtime_open"].append({
                "claim": "selected Unity API target to bridge same-invocation causality",
                "reason": "both entries executed, but this entry-only run does not pair one Unity invocation to one bridge entry",
            })
        result["next_work"] = [
            "resolve the 259 retained caller keys and three runtime execution edges against authoritative native code",
            "use the two complete ECS address lifecycles to locate lifecycle and scheduling identity anchors offline",
            "prepare another runtime plan only for reset, job execution, or same-invocation gaps that remain after static joins",
        ]
        result["runtime_required_now"] = False
    if task_receiver_join is not None:
        receiver_summary = task_receiver_join["summary"]
        required = {
            "matched_task_contexts": 25,
            "direct_animator_tasks": 22,
            "component_animator_tasks": 3,
            "unique_direct_animator_addresses": 1,
            "unique_animator_component_addresses": 1,
            "unique_trigger_owner_entities": 1,
        }
        if any(receiver_summary.get(key) != value for key, value in required.items()):
            raise ValueError("task receiver join does not satisfy the captured Remielle signature")
        result["sources"]["task_receiver_runtime_join"] = _source(task_receiver_join_path)
        result["closed_bounded"].append({
            "claim": "Remielle BehaviorTree parameter tasks to runtime receivers",
            **receiver_summary,
            "scope": "25 retained task contexts plus native field-consumption instructions; current-process addresses only",
        })
        for row in result["runtime_open"]:
            if row["claim"] == "same-instance Animator stage to parameter-consumer causality":
                row["reason"] = "task to receiver is closed for 25 Remielle contexts; fixed-update stage to this specific tree instance remains unpaired"
            elif row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = "captured BehaviorManager callbacks synchronously reach task receivers; the upstream Ability/condition selection and other asynchronous paths remain open"
        result["next_work"] = [
            "trace the authoritative upstream selector for the observed Remielle Decision-tree indices offline",
            "separate the three trigger-component receiver paths from the 22 direct Unity Animator paths",
            "prepare one exact reusable plan only for unresolved upstream pairing, lifecycle, ordinary-special, and per-move attribution",
        ]
        result["runtime_required_now"] = False
    if field_runtime_join is not None:
        checks = field_runtime_join["checks"]
        if checks.get("invalid_static_join_count") or checks.get(
                "unresolved_caller_evidence_count"):
            raise ValueError("field runtime join contains unresolved or invalid caller evidence")
        result["sources"]["field_runtime_static_join"] = _source(field_runtime_join_path)
        result["closed_bounded"].append({
            "claim": "retained caller native ownership and static joins",
            "caller_evidence": checks["caller_evidence_count"],
            "pdata_owned": checks["pdata_owned_caller_evidence_count"],
            "logical_runtime_edges": checks["logical_edge_count"],
            "catalog_anchored_edges": checks["catalog_anchored_edge_count"],
            "static_matched_callers": checks["static_matched_caller_evidence_count"],
            "catalog_matched_callers": checks["catalog_matched_caller_evidence_count"],
            "scope": "runtime return address plus bound-module PDATA and audited callsites",
        })
        result["offline_open"] = [row for row in result["offline_open"]
                                  if row["claim"] != "remaining controller runtime caller identities"]
        result["offline_open"].append({
            "claim": "retained caller semantic identities outside current static catalogs",
            "unmatched_rows": checks["unmatched_caller_evidence_count"],
            "reason": "native owners and exact callsites are known; most engine functions have no authoritative semantic catalog name",
        })
    if caller_stage_profile is not None:
        if field_runtime_join is None:
            raise ValueError("caller stage profile requires field runtime static join")
        result["sources"]["caller_stage_profile"] = _source(caller_stage_profile_path)
        stage_summary = caller_stage_profile["summary"]
        result["closed_bounded"].append({
            "claim": "retained caller action-window profile",
            "retained_caller_keys": stage_summary["retained_caller_keys"],
            "single_window_callers": stage_summary["single_action_window_callers"],
            "priority_candidates": stage_summary["single_action_window_priority_candidates"],
            "scope": "lossless bounded checkpoint deltas; priority only, not move attribution",
        })
        for row in result["offline_open"]:
            if row["claim"] == "retained caller semantic identities outside current static catalogs":
                row["stage_priority_candidates"] = stage_summary[
                    "single_action_window_priority_candidates"]
        result["next_work"] = [
            "statically decode and catalog the eight single-action-window caller candidates before choosing any new hooks",
            "join task and ECS observed addresses only where authoritative lifecycle or scheduling evidence exists",
            "prepare another runtime plan only if reset, job execution, or same-invocation gaps survive those offline joins",
        ]
        result["runtime_required_now"] = False
    if caller_static_decode is not None:
        if caller_stage_profile is None:
            raise ValueError("caller static decode requires caller stage profile")
        summary_decode = caller_static_decode["summary"]
        if summary_decode["priority_callsites"] != summary_decode["direct_target_verified_callsites"]:
            raise ValueError("not every priority callsite has its selected direct target verified")
        if summary_decode["runtime_functions"] != summary_decode["fully_decoded_functions"]:
            raise ValueError("not every priority runtime function is fully decoded")
        result["sources"]["caller_priority_static_decode"] = _source(caller_static_decode_path)
        result["closed_bounded"].append({
            "claim": "priority retained caller complete native decode",
            **summary_decode,
            "scope": "seven PDATA owners and eight selected callsites; no inferred semantic names",
        })
    if caller_ghidra_join is not None:
        if caller_static_decode is None:
            raise ValueError("caller Ghidra join requires caller static decode")
        summary_ghidra = caller_ghidra_join["summary"]
        if summary_ghidra["functions"] != summary_ghidra["instruction_agreement_functions"]:
            raise ValueError("priority caller Capstone/Ghidra instruction disagreement")
        if summary_ghidra["capstone_instructions"] != summary_ghidra["ghidra_instructions"]:
            raise ValueError("priority caller Capstone/Ghidra instruction count mismatch")
        result["sources"]["caller_priority_ghidra_join"] = _source(caller_ghidra_join_path)
        result["closed_bounded"].append({
            "claim": "priority retained caller independent disassembler agreement",
            **summary_ghidra,
            "scope": "complete instruction agreement after mechanical mnemonic alias normalization",
        })
        result["next_work"] = [
            "do not invent semantic names for the seven decoded UnityPlayer owners without an authoritative catalog",
            "use the decoded callsites only as bounded stage/callsite evidence",
            "finish static reset/job gap separation before selecting the next runtime observation",
        ]
        result["runtime_required_now"] = False
    if static_gap is not None:
        checks = static_gap["checks"]
        required = ("all_reset_implementations_source_verified", "all_reset_entries_not_observed",
                    "parallel_job_static_chain_source_verified", "parallel_job_wrapper_not_observed")
        if not all(checks.get(key) for key in required):
            raise ValueError("controller static gap analysis did not satisfy all bounded checks")
        result["sources"]["controller_static_gap_analysis"] = _source(static_gap_analysis_path)
        result["closed_bounded"].extend([
            {
                "claim": "selected parameter task OnReset implementation semantics",
                "implementations": checks["reset_implementation_count"],
                "scope": "complete PDATA decode plus harvested field offsets and implicit-conversion identities; execution not implied",
            },
            {
                "claim": "selected parallel job concrete/static dispatch chain",
                "concrete_execute_rva": static_gap["parallel_job_dispatch"]["concrete_execute_thunk"]["rva"],
                "generated_wrapper_rva": static_gap["parallel_job_dispatch"]["generated_wrapper"]["rva"],
                "shared_body_rva": static_gap["parallel_job_dispatch"]["shared_body"]["rva"],
                "consumer_rva": static_gap["parallel_job_dispatch"]["shared_body"]["consumer_rva"],
                "scope": "source-verified static chain; runtime branch selection not implied",
            },
        ])
        for row in result["runtime_open"]:
            if row["claim"] == "task reset lifecycle for selected parameter tasks":
                row["reason"] = "OnReset implementation is closed statically, but callback execution and object lifetime were not observed"
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = "the selected job chain is closed statically, but its Remielle runtime branch and cross-thread instance link were not observed"
        result["next_work"] = [
            "build one narrow reusable plan for same-invocation pairing, lifecycle identity, and cross-thread instance correlation",
            "keep ordinary special as a separate action-coverage requirement because the trial supplied enhanced special",
            "do not repeat broad gameplay for the four OnReset bodies or the selected job dispatch implementation",
        ]
        result["runtime_required_now"] = True
    if runtime_closure_acceptance is not None:
        bridge_rows = [row for row in runtime_closure_caller_join.get("runtime_callsite_rows", [])
                       if row.get("callee_point", "").startswith(
                           "GameAssembly.animator-fixed-update-bridge@")
                       and row.get("caller_runtime_function", {}).get("begin_rva") ==
                           api["invoke"]["invokerRva"]
                       and row.get("observation_count", 0) > 0]
        if len(bridge_rows) != 1:
            raise ValueError("runtime closure does not uniquely prove invoker to bridge execution")
        bridge_row = bridge_rows[0]
        caller = bridge_row["caller_runtime_function"]
        if not (caller["begin_rva"] <= bridge_row["callsite_rva"] < caller["end_rva"]):
            raise ValueError("invoker bridge callsite is outside its runtime function")

        unique_trees = [row for row in task_context_static_join.get("behavior_trees", [])
                        if row.get("identity_status") == "UNIQUE_STATIC_TASK_SIGNATURE_MATCH"]
        if len(unique_trees) != 1:
            raise ValueError("runtime closure lacks one unique static BehaviorTree match")
        tree = unique_trees[0]
        candidates = tree.get("candidate_static_trees", [])
        if len(candidates) != 1 or candidates[0].get("root_tree") != (
                "Behavior_Avatar_RemielleOrigin_Decision"):
            raise ValueError("unique runtime tree is not the authoritative Remielle Origin root")
        if task_context_static_join["summary"].get("ambiguous_static_tree_matches") != 0:
            raise ValueError("runtime closure has ambiguous static tree matches")

        job_prefixes = (
            "ParallelForJobStruct<IKNHGFBHLLK>.Execute@",
            "IKNHGFBHLLK.shared-execute-body@",
            "ODKPBBAJAEG.KBPGJAPPBLI@",
        )
        job_points = [row for row in runtime_closure_acceptance.get("points", [])
                      if row.get("point", "").startswith(job_prefixes)]
        if len(job_points) != 3 or any(row.get("status") !=
                                      "NOT_OBSERVED_IN_COVERED_WINDOW" for row in job_points):
            raise ValueError("selected parallel job branch lacks complete covered non-observation")

        result["sources"].update({
            "runtime_closure_acceptance": _source(runtime_closure_acceptance_path),
            "runtime_closure_caller_join": _source(runtime_closure_caller_join_path),
            "task_context_static_join": _source(task_context_static_join_path),
        })
        result["closed_bounded"].extend([
            {
                "claim": "live Animator invoker to selected bridge same-invocation execution",
                "invoker_rva": caller["begin_rva"],
                "bridge_rva": api["invoke"]["bridgeCodeRva"],
                "callsite_rva": bridge_row["callsite_rva"],
                "event_count": bridge_row["observation_count"],
                "scope": "accepted current-process generation and exact runtime return-address callsite",
            },
            {
                "claim": "Remielle Origin expanded BehaviorTree runtime candidate",
                "behavior_tree_address": tree["behavior_tree_address"],
                "root_tree": candidates[0]["root_tree"],
                "matched_task_signatures": len(tree.get("observed_task_signature", [])),
                "scope": "unique game-derived root-tree task signature; ObjectCandidate, not EntityIdentity",
            },
            {
                "claim": "selected IKNHGFBHLLK parallel-job branch non-selection",
                "points": [row["point"] for row in job_points],
                "scope": "not observed in the complete marked trial phase-flow window and generation",
            },
            {
                "claim": "runtime controller dispatch chain",
                "source_identified_rows": runtime_closure_caller_join["summary"]["source_identified_rows"],
                "runtime_edges": runtime_closure_caller_join["summary"]["runtime_edges"],
                "scope": "ODK system, BehaviorManager Tick/RunTask, and parameter callback callsites",
            },
        ])
        for row in result["runtime_open"]:
            if row["claim"] == "selected Unity API target to bridge same-invocation causality":
                row["claim"] = "selected Unity API target to Animator invoker same-invocation causality"
                row["reason"] = "invoker to bridge is now observed; the upstream selected API target to invoker remains unpaired"
            elif row["claim"] == "native object lifecycle to Remielle entity identity":
                row["reason"] = "the runtime tree candidate uniquely matches Remielle Origin, but has no native creation generation or destruction boundary"
            elif row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = "the selected IKNHGFBHLLK branch was not chosen in the covered trial phase-flow path; the actual scheduling path remains open"
        result["next_work"] = [
            "join the 25 Remielle task signatures to serialized fields and Animator receivers offline",
            "trace the actual phase-flow scheduling branch instead of repeating the excluded IKNHGFBHLLK hypothesis",
            "prepare a new runtime plan only for remaining same-instance, lifecycle, ordinary-special, and per-move gaps after those joins",
        ]
        result["runtime_required_now"] = False
    if task_ancestor_join is not None:
        ancestor_summary = task_ancestor_join["summary"]
        required = {
            "joined_task_signatures": 25,
            "serialized_subtrees": 2,
            "unique_ancestor_chains": 11,
            "conditional_evaluator_nodes": 5,
            "random_weight_nodes": 2,
        }
        if any(ancestor_summary.get(key) != value for key, value in required.items()):
            raise ValueError("task ancestor join does not satisfy the captured Remielle signature")
        condition_keys: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row in task_ancestor_join.get("task_ancestor_rows", []):
            for condition in row.get("ancestor_conditions", []):
                key = (
                    condition.get("tree"), condition.get("task_index"),
                    condition.get("conditional_task_type"),
                    condition.get("integer1_shared_name"),
                    condition.get("integer2_constant_raw"),
                    condition.get("operation_raw"),
                )
                condition_keys[key] = condition
        conditions = [condition_keys[key] for key in sorted(
            condition_keys, key=lambda value: tuple(str(item) for item in value))]
        if len(conditions) != ancestor_summary["conditional_evaluator_nodes"]:
            raise ValueError("task ancestor condition rows do not match summary")
        result["sources"]["task_ancestor_static_join"] = _source(task_ancestor_join_path)
        result["closed_bounded"].append({
            "claim": "observed Remielle tasks to serialized ancestor branches",
            **ancestor_summary,
            "conditions": conditions,
            "scope": "authoritative expanded BehaviorTree structure joined by native task type, parameter name, and serialized value; runtime condition outcomes are not implied",
        })
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = ("the 25 observed tasks now have their serialized Remielle ancestor "
                                 "chains and five raw IntComparison conditions; runtime condition "
                                 "outcomes, selector choice, and other asynchronous paths remain open")
        result["next_work"] = [
            "recover the authoritative enum meaning of IntComparison operation_raw=2 offline if present in harvested metadata or native code",
            "compile one reusable narrow plan for the five condition outcomes, selector choice, lifecycle identity, and remaining same-invocation edge",
            "keep ordinary special and per-move attribution as explicit action-coverage gaps; do not repeat broad controller capture",
        ]
        result["runtime_required_now"] = False
    if int_comparison_enum is not None:
        selected = int_comparison_enum.get("selected_runtime_value", {})
        if (selected.get("raw_value"), selected.get("enum_member"),
                selected.get("predicate_instruction"), selected.get("native_predicate")) != (
                2, "EqualTo", "sete", "equal"):
            raise ValueError("IntComparison raw value 2 is not natively proven as equality")
        mappings = int_comparison_enum.get("mappings", [])
        if len(mappings) != 6 or [row.get("raw_value") for row in mappings] != list(range(6)):
            raise ValueError("IntComparison enum decode is incomplete")
        result["sources"]["int_comparison_enum_decode"] = _source(int_comparison_enum_path)
        result["closed_bounded"].append({
            "claim": "IntComparison serialized operation numeric semantics",
            "operation_field_offset": int_comparison_enum["operation_field_offset"],
            "mappings": mappings,
            "selected_runtime_value": selected,
            "scope": "harvested runtime type layout plus complete GameAssembly OnUpdate jump-table decode",
        })
        result["next_work"] = [
            "trace the authoritative tree stop/abort paths to decide whether unobserved task OnReset is conditional or required",
            "compile one reusable narrow plan for five condition outcomes, selector choice, lifecycle identity, and the remaining same-invocation edge",
            "keep ordinary special and per-move attribution as explicit action-coverage gaps; do not repeat broad controller capture",
        ]
        result["runtime_required_now"] = False
    if task_reset_audit is not None:
        coverage = task_reset_audit.get("coverage", {})
        conclusion = task_reset_audit.get("conclusion", {})
        dispatch = task_reset_audit.get("dispatch", {})
        if (coverage.get("behavior_manager_methods") != 99 or
                coverage.get("unique_pdata_functions") != 91 or
                coverage.get("pdata_less_bounded_heads") != 8 or
                not coverage.get("all_pdata_functions_completely_decoded")):
            raise ValueError("task reset audit coverage is incomplete")
        if (conclusion.get("behavior_manager_dispatches_on_reset") is not False or
                not conclusion.get("runtime_completion_dispatches_present") or
                dispatch.get("OnReset") or not dispatch.get("OnEnd") or
                not dispatch.get("OnBehaviorComplete")):
            raise ValueError("task reset audit does not support reclassification")
        result["sources"]["task_reset_dispatch_audit"] = _source(task_reset_audit_path)
        result["closed_bounded"].append({
            "claim": "BehaviorManager runtime task lifecycle dispatch inventory",
            **coverage,
            "dispatch_counts": {name: len(rows) for name, rows in dispatch.items()},
            "scope": "all harvested BehaviorManager methods; OnReset absence is bounded to this scheduler inventory",
        })
        result["runtime_open"] = [row for row in result["runtime_open"]
                                  if row["claim"] != "task reset lifecycle for selected parameter tasks"]
        result["classified_not_gameplay_repetition_gaps"].append({
            "claim": "selected parameter task OnReset runtime callback",
            "policy": "do not repeat gameplay to force it",
            "reason": "BehaviorManager dispatches OnEnd and OnBehaviorComplete but has no OnReset virtual dispatch; selected OnReset bodies are already statically decoded",
        })
        result["next_work"] = [
            "compile one reusable narrow plan for five condition outcomes, selector choice, lifecycle identity, and the remaining same-invocation edge",
            "retain OnEnd and OnBehaviorComplete as the native runtime lifecycle boundaries; do not request gameplay for OnReset",
            "keep ordinary special and per-move attribution as explicit action-coverage gaps; do not repeat broad controller capture",
        ]
        result["runtime_required_now"] = False
    if exact_closure_plan is not None:
        points = exact_closure_plan.get("points", [])
        exact_callers = sum(len(row.get("retention", {}).get("exact_callers", []))
                            for row in points)
        if (exact_closure_plan.get("plan_id") != "controller-exact-closure-v1" or
                len(points) != 5 or exact_callers != 2):
            raise ValueError("exact closure plan does not match the bounded five-point unit")
        if exact_closure_plan.get("scope", {}).get("automatic_stop") is not False:
            raise ValueError("exact closure plan must not impose automatic stop")
        result["sources"]["controller_exact_closure_plan"] = _source(exact_closure_plan_path)
        result["next_capture"] = {
            "plan_id": exact_closure_plan["plan_id"],
            "plan_revision": exact_closure_plan["plan_revision"],
            "points": len(points), "preselected_exact_callers": exact_callers,
            "purpose": exact_closure_plan["scope"]["purpose"],
            "qualification_then_formal_runtime_rounds": 1,
        }
        result["next_work"] = [
            "with the game running before trial, execute the prepared five-site patch/restore qualification request",
            "apply caller-continuation completion to the two preselected exact callers and start the same plan without rebuilding the DLL",
            "perform one marked action session covering phase-flow conditions, trigger use, trial exit, and the available move-attribution cases",
        ]
        result["runtime_required_now"] = True
    if exact_runtime is not None:
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = ("the five authoritative Remielle condition signatures and their "
                                 "ConditionalEvaluator task-owner relations are now observed; selector "
                                 "choice and other asynchronous queue edges remain open")
            elif row["claim"] == "native object lifecycle to Remielle entity identity":
                row["reason"] = ("load/destroy boundaries and the five-condition owner establish "
                                 "ObjectCandidates, but no native creation generation or Remielle "
                                 "EntityIdentity binding has been observed")
        result.pop("next_capture", None)
        result["next_work"] = [
            "merge the same-session five-condition owner relation into the native controller execution graph",
            "statically narrow selector choice and the upstream selected Unity API target to invoker edge before designing another runtime unit",
            "retain ordinary special independent coverage and per-move attribution as explicit gaps; do not repeat broad gameplay capture",
        ]
        result["runtime_required_now"] = False
    if selector_join is not None:
        if selector_join.get("schema") != "uc.controller-selector-static-runtime-join.v1":
            raise ValueError("unsupported controller selector join")
        checks = selector_join.get("checks", {})
        if not checks or not all(checks.values()):
            raise ValueError("controller selector join is incomplete")
        selectors = selector_join.get("selectors", [])
        if len(selectors) != 2 or not all(row.get("both_serialized_children_observed")
                                          for row in selectors):
            raise ValueError("controller selector evidence does not close both scoped nodes")
        result["sources"]["controller_selector_static_runtime_join"] = _source(selector_join_path)
        result["closed_bounded"].append({
            "claim": "Remielle Origin Confrontation random-weight selector choices",
            "selectors": [{"serialized_task_index": row["serialized_task_index"],
                           "runtime_task_index": row["runtime_task_index"],
                           "run_call_count": row["run_call_count"],
                           "branches": row["branches"]} for row in selectors],
            "scope": ("two structurally joined RandomExcuteWithSharedWeight nodes; both native "
                      "child dispatch edges observed in the preserved runtime session; no direct "
                      "runtime CAB/PathID or EntityIdentity claim"),
        })
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = ("the five Remielle condition signatures, owner relation, and both "
                                 "outcomes of both Confrontation random-weight selectors are closed; "
                                 "other upstream asynchronous scheduling edges remain open")
    if upstream_invoker_join is not None:
        if upstream_invoker_join.get("schema") != "uc.controller-upstream-invoker-join.v1":
            raise ValueError("unsupported upstream invoker join")
        checks = upstream_invoker_join.get("checks", {})
        if not checks or not all(checks.values()):
            raise ValueError("upstream invoker join is incomplete")
        result["sources"]["controller_upstream_invoker_join"] = _source(upstream_invoker_join_path)
        result["closed_bounded"].append({
            "claim": "selected Unity API target to Animator invoker to bridge same-invocation chain",
            **upstream_invoker_join["static_callsite"],
            **upstream_invoker_join["runtime_join"],
            "scope": "complete static callsite decode joined to exact runtime caller continuation and selected bridge",
        })
        result["runtime_open"] = [row for row in result["runtime_open"] if row["claim"] !=
                                  "selected Unity API target to Animator invoker same-invocation causality"]
    if selector_join is not None or upstream_invoker_join is not None:
        result.pop("next_capture", None)
        result["next_work"] = [
            "statically identify the remaining upstream asynchronous scheduling callsites and lifecycle creation sites",
            "compile one combined low-frequency runtime plan for same-instance stage causality, lifecycle identity, and unresolved upstream queue edges",
            "combine ordinary-special and per-move attribution in the same action unit where the trial permits; keep inaccessible ordinary special separately classified",
        ]
        result["runtime_required_now"] = False
    if final_runtime is not None:
        if final_runtime.get("schema") != "uc.controller-final-runtime-analysis.v1":
            raise ValueError("unsupported final runtime analysis")
        integrity = final_runtime.get("integrity", {})
        if (integrity.get("store_clean") is not True
                or integrity.get("lost_events") != 0
                or integrity.get("manifest_errors") != []
                or integrity.get("complete_checkpoint_intervals") != 33):
            raise ValueError("final runtime analysis is not complete clean evidence")
        final_summary = final_runtime["summary"]
        if (final_summary.get("behavior_loads") != 12
                or final_summary.get("behavior_completions") != 12
                or final_summary.get("unique_all_three_task_family_receivers") != 1):
            raise ValueError("final runtime analysis lacks required bounded joins")
        stage_events = sum(
            count for window in final_runtime.get("action_windows", [])
            for point, count in window.get("point_counts", {}).items()
            if "AnimatorStage." in point)
        result["sources"]["controller_final_runtime_analysis"] = _source(
            final_runtime_analysis_path)
        result["closed_bounded"].extend([
            {
                "claim": "BehaviorManager load-complete-destroy boundaries",
                "loads": final_summary["behavior_loads"],
                "load_completions": final_summary["behavior_completions"],
                "loaded_instances_with_destroy":
                    final_summary["loaded_behaviors_with_destroy"],
                "destroyed_preexisting_or_unobserved":
                    final_summary["destroyed_preexisting_or_unobserved"],
                "multi_behavior_entity_ids": final_summary["multi_behavior_entity_ids"],
                "decoded_behavior_names": final_summary["decoded_behavior_names"],
                "decoded_external_behavior_names":
                    final_summary["decoded_external_behavior_names"],
                "scope": ("one clean process generation; multiple Behavior instances may "
                          "belong to one entity ID and do not establish address reuse or "
                          "Remielle EntityIdentity"),
            },
            {
                "claim": "parameter-task to native Animator receiver address joins",
                "parameter_task_samples": final_summary["parameter_task_samples"],
                "same_thread_consecutive_consumer_joins":
                    final_summary["same_thread_consecutive_task_consumer_joins"],
                "unique_all_three_task_family_receiver_candidates":
                    final_runtime["unique_all_three_task_family_receiver_candidates"],
                "scope": ("current-process ObservedAddress plus consecutive stored event "
                          "evidence; not serialized task or entity identity"),
            },
            {
                "claim": "lossless final action-window parameter and Animator-stage coverage",
                "checkpoint_intervals": final_summary["checkpoint_intervals"],
                "selected_parameter_calls": final_summary["selected_parameter_calls"],
                "animator_stage_events": stage_events,
                "scope": ("33 bounded user-action intervals; mixed preparation and multi-actor "
                          "windows remain labelled rather than over-attributed"),
            },
        ])
        for row in result["runtime_open"]:
            if row["claim"] == "same-instance Animator stage to parameter-consumer causality":
                row["reason"] = (
                    f"{stage_events} stage events and "
                    f"{final_summary['selected_parameter_calls']} selected consumers are lossless, "
                    "but captured stage-object addresses do not equal receiver addresses and no "
                    "native field path has yet proved the same-instance join")
            elif row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["reason"] = (
                    f"{final_summary['same_thread_consecutive_task_consumer_joins']} task-to-consumer "
                    "adjacencies and one three-family receiver candidate are observed, but this "
                    "generation did not capture TaskExecutor tree-to-task membership or the "
                    "remaining asynchronous queue edges")
            elif row["claim"] == "native object lifecycle to Remielle entity identity":
                row["reason"] = (
                    "12 load/complete pairs and 10 matching destroy boundaries are observed; "
                    "all 12 captured BehaviorSource and ExternalBehavior source-name strings "
                    "decode to the generic literal 'Behavior', so this plan did not record the "
                    "native Unity object-name binding needed to identify either entity as Remielle")
            elif row["claim"] == "per-move attribution and complete call/return pairing":
                row["reason"] = (
                    "33 lossless action intervals preserve selected parameter/stage profiles, but "
                    "some windows intentionally contain setup, multiple actors, or multiple moves; "
                    "entry-only records do not establish complete call/return pairing")
        result.pop("next_capture", None)
        result["next_work"] = [
            "offline-decode the two captured Animator stage functions to seek a source-verified stage-object to receiver field path",
            "offline-identify Behavior/TaskExecutor creation and tree-membership callsites that can bind lifecycle instances to the authoritative Remielle tree",
            "only if those static joins remain insufficient, compile one combined follow-up unit for same-generation tree membership and stage receiver identity; keep inaccessible ordinary special separately classified",
        ]
        result["runtime_required_now"] = False
    if animator_stage_static is not None:
        result["sources"]["animator_stage_receiver_static_join"] = _source(
            animator_stage_static_join_path)
        result["closed_bounded"].append({
            "claim": "native Animator to consumer to stage static ownership path",
            "path": animator_stage_static["static_path"],
            "scope": ("source-verified UnityPlayer instructions: A stores S at A+0x6a0; "
                      "S drives the evaluator and its machine-array child stage objects"),
        })
        for row in result["runtime_open"]:
            if row["claim"] == "same-instance Animator stage to parameter-consumer causality":
                row["reason"] = (
                    "the native ownership path A->[A+0x6a0]=S->evaluator->stage children is "
                    "closed statically; only the same-generation equality between the selected "
                    "Remielle Animator receiver A and observed consumer S remains unobserved")
    if final_identity is not None:
        chain = final_identity["identity_chain"]
        tree = chain["behavior_tree_instance"]
        executor = chain["task_executor_membership"]
        receiver = chain["animator_receiver_candidate"]
        result["sources"]["controller_final_identity_join"] = _source(
            final_identity_join_path)
        result["closed_bounded"].extend([
            {
                "claim": "native Remielle entity to Behavior instance and authoritative tree identity",
                "native_entity_id": chain["entity_identity"]["native_entity_id"],
                "behavior_address": chain["behavior_instance"]["behavior_address"],
                "behavior_tree_address": tree["address"],
                "root_tree": tree["authoritative_root_tree"],
                "matched_task_signatures": tree["matched_task_signatures"],
                "scope": ("same session/generation load-complete boundary plus unique "
                          "game-derived Remielle Origin serialized-task signature"),
            },
            {
                "claim": "Remielle TaskExecutor membership to selected Animator consumer receiver",
                "task_contexts": executor["contexts"],
                "task_consumer_joins": receiver["same_thread_consecutive_task_consumer_joins"],
                "animator_receiver": receiver["address"],
                "task_families": receiver["task_families"],
                "scope": ("same generation, exact tree/index register contract and consecutive "
                          "same-thread task-to-consumer events"),
            },
        ])
        result["runtime_open"] = [
            row for row in result["runtime_open"]
            if row["claim"] != "native object lifecycle to Remielle entity identity"
        ]
        for row in result["runtime_open"]:
            if row["claim"] == "Task/Ability to Animator cross-thread scheduling causality":
                row["claim"] = "remaining Ability/ECS asynchronous scheduling causality"
                row["reason"] = (
                    f"the Remielle tree supplies {executor['contexts']} native TaskExecutor "
                    f"contexts and {receiver['same_thread_consecutive_task_consumer_joins']} "
                    "same-thread joins to one Animator receiver; only scheduling paths outside "
                    "this task-to-Animator parameter route remain open")
    if animator_stage_static is not None or final_identity is not None:
        result.pop("next_capture", None)
        result["next_work"] = [
            "compile one low-frequency same-generation observation for S=[A+0x6a0] and ccec40(RCX=S), reusing the unified DLL",
            "keep inaccessible ordinary special as a separately classified action-coverage gap",
            "retain mixed-window per-move attribution and unrelated asynchronous Ability/ECS paths as explicit bounded gaps",
        ]
        result["runtime_required_now"] = False
    if legacy_animator_stage is not None:
        chain = legacy_animator_stage["instance_chain"]
        result["sources"]["legacy_animator_stage_instance_join"] = _source(
            legacy_animator_stage_instance_join_path)
        result["closed_bounded"].append({
            "claim": "Remielle native Animator to stage same-instance ownership",
            "pid": legacy_animator_stage["pid"],
            "controller": chain["controller_name"],
            "native_animator_A": chain["native_animator_A"],
            "consumer_S": chain["consumer_S"],
            "field_offset": chain["field_offset"],
            "consumer_callback_rva": chain["consumer_callback_rva"],
            "indexed_ccec40_entry_events_for_S":
                chain["indexed_ccec40_entry_events_for_S"],
            "scope": ("clean preserved PID generation: managed Remielle controller identity "
                      "to native A, [A+0x6a0]=S, S as ccec40 RCX, then the independently "
                      "decoded evaluator-to-stage path"),
        })
        result["runtime_open"] = [
            row for row in result["runtime_open"]
            if row["claim"] != "same-instance Animator stage to parameter-consumer causality"
        ]
        result.pop("next_capture", None)
        result["next_work"] = [
            "continue offline from the already decoded ODK/BehaviorManager paths to classify only the remaining Ability/ECS asynchronous scheduling edges",
            "keep inaccessible ordinary special as a separately classified action-coverage gap rather than requesting an impossible trial action",
            "derive the strongest per-move attribution possible from the 33 lossless windows before deciding whether any new call/return probe is justified",
        ]
        result["runtime_required_now"] = False
    if ability_executor_coverage is not None:
        coverage_summary = ability_executor_coverage["summary"]
        result["sources"]["ability_executor_coverage"] = _source(
            ability_executor_coverage_path)
        result["closed_bounded"].append({
            "claim": "188-type Ability executor native coverage inventory",
            "types": coverage_summary["types"],
            "positions_complete_types": coverage_summary["positions_complete_types"],
            "methods": coverage_summary["methods"],
            "exact_pdata_entries": coverage_summary["exact_pdata_entries"],
            "fully_decoded_pdata_bodies": coverage_summary["fully_decoded_pdata_bodies"],
            "pdata_less_entries": coverage_summary["pdata_less_entries"],
            "direct_calls": coverage_summary["direct_calls"],
            "indirect_calls": coverage_summary["indirect_calls"],
            "scope": ("all 188 serialized types have exact asset positions and a per-method "
                      "native boundary/decode account; decoding is not promoted to complete semantics"),
        })
        result["runtime_open"] = [
            row for row in result["runtime_open"]
            if row["claim"] != "remaining Ability/ECS asynchronous scheduling causality"
        ]
        result["offline_open"] = [
            row for row in result["offline_open"]
            if row["claim"] != "Ability executor semantic and external dependency audit"
        ]
        result["offline_open"].append({
            "claim": "Ability executor semantic and external dependency audit",
            "types": coverage_summary["types"],
            "pdata_less_entries": coverage_summary["pdata_less_entries"],
            "direct_targets_outside_selected_catalog": (
                coverage_summary["direct_calls"]
                - coverage_summary["direct_calls_to_selected_catalog"]),
            "indirect_calls": coverage_summary["indirect_calls"],
            "reason": ("ODK-to-BehaviorManager-to-RunTask and the selected Remielle "
                       "Task-to-Animator route are already runtime-observed; the remaining "
                       "188-type work is static semantic/dependency classification, not one "
                       "unspecified asynchronous runtime edge"),
        })
        result["next_work"] = [
            "rank the 188-type external direct targets and 353 indirect callsites by Remielle asset occurrence and controller relevance",
            "close source-identifiable state reads, writes, registration and cancellation edges offline before proposing any hook",
            "keep inaccessible ordinary special and complete call/return attribution as separately bounded runtime gaps",
        ]
        result["runtime_required_now"] = False
    if action_window_attribution is not None:
        attribution_summary = action_window_attribution["summary"]
        result["sources"]["action_window_receiver_attribution"] = _source(
            action_window_attribution_path)
        result["closed_bounded"].append({
            "claim": "bounded Remielle receiver attribution across final action windows",
            "windows": attribution_summary["windows"],
            "complete_lossless_windows": attribution_summary["complete_lossless_windows"],
            "windows_with_direct_remielle_task_consumer_events":
                attribution_summary["windows_with_direct_remielle_task_consumer_events"],
            "windows_with_same_address_receiver_activity":
                attribution_summary["windows_with_same_address_receiver_activity"],
            "scope": ("direct TaskExecutor adjacency is distinct from same-address activity; "
                      "zero traffic and checkpoint labels are not promoted to move non-execution or identity"),
        })
        for row in result["runtime_open"]:
            if row["claim"] == "per-move attribution and complete call/return pairing":
                row["reason"] = (
                    f"all {attribution_summary['windows']} windows are lossless; "
                    f"{attribution_summary['windows_with_direct_remielle_task_consumer_events']} "
                    "window has direct consecutive Remielle Task-to-consumer evidence and "
                    f"{attribution_summary['windows_with_same_address_receiver_activity']} "
                    "have same-address receiver activity, but checkpoint labels, mixed actors, "
                    "entry-only events, and post-reentry identity prevent complete per-move "
                    "call/return attribution")
        result["runtime_required_now"] = False
    if ability_dependency_frontier is not None:
        dependency_summary = ability_dependency_frontier["summary"]
        result["sources"]["ability_executor_dependency_frontier"] = _source(
            ability_dependency_frontier_path)
        result["closed_bounded"].append({
            "claim": "188-type Ability external direct dependency frontier",
            "external_direct_calls": dependency_summary["external_direct_calls"],
            "unique_external_direct_targets": dependency_summary["unique_external_direct_targets"],
            "source_identified_or_annotated_targets":
                dependency_summary["source_identified_or_annotated_targets"],
            "stratum_counts": dependency_summary["stratum_counts"],
            "target_boundary_counts": dependency_summary["target_boundary_counts"],
            "scope": ("exact decoded direct callsites and source RVA joins; frequency strata "
                      "are not promoted to semantic identities"),
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "external_direct_calls": dependency_summary["external_direct_calls"],
                    "unique_external_direct_targets": dependency_summary["unique_external_direct_targets"],
                    "unidentified_direct_targets": (
                        dependency_summary["unique_external_direct_targets"]
                        - dependency_summary["source_identified_or_annotated_targets"]),
                    "source_identified_or_annotated_direct_targets":
                        dependency_summary["source_identified_or_annotated_targets"],
                })
                row["reason"] = (
                    "the direct dependency frontier is fully enumerated and source names are "
                    "joined where harvested catalogs permit; unidentified direct targets and "
                    "indirect dispatch still require bounded offline classification")
        result["next_work"] = [
            "mechanically join generated native wrapper stubs to the 353 indirect callsites",
            "perform bounded dataflow on object/vtable and register dispatch without guessed callees",
            "defer runtime slot reads until static wrapper and relocation evidence is exhausted",
        ]
        result["runtime_required_now"] = False
    if ability_indirect_call_join is not None:
        indirect_summary = ability_indirect_call_join["summary"]
        result["sources"]["ability_executor_indirect_call_join"] = _source(
            ability_indirect_call_join_path)
        result["closed_bounded"].append({
            "claim": "188-type Ability indirect callsite mechanical classification",
            **indirect_summary,
            "scope": ("same-slot generated wrapper identities, PE DIR64 targets, and distinct "
                      "unresolved RIP/object/register forms; no inferred callees"),
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "indirect_exact_semantic_wrapper_callsites":
                        indirect_summary["exact_semantic_wrapper_callsites"],
                    "indirect_exact_static_target_callsites":
                        indirect_summary["exact_static_target_without_semantic_identity_callsites"],
                    "indirect_without_exact_target_identity":
                        indirect_summary["remaining_without_exact_target_identity"],
                })
                row["reason"] = (
                    "all indirect forms are now mechanically classified: exact wrapper identities "
                    "and static relocated targets are separated from unbacked runtime slots, "
                    "object/vtable slots, and register dispatch; remaining identities require "
                    "additional authoritative catalogs or bounded dataflow")
        unresolved_slot_candidates = indirect_summary.get(
            "unique_runtime_slot_candidates_without_exact_identity")
        slot_work = (
            f"resolve the {unresolved_slot_candidates} unique initialized-slot candidates "
            "without exact identity only after static owner evidence is exhausted"
            if unresolved_slot_candidates is not None else
            "resolve remaining initialized-slot candidates only after static owner evidence is exhausted"
        )
        result["next_work"] = [
            slot_work,
            "trace the 26 object/vtable and 12 register dispatch sites through exact class and interface metadata",
            "continue direct-target semantic/dependency audit before considering a runtime initialized-slot snapshot",
        ]
        result["runtime_required_now"] = False
    if ability_external_target_body_ledger is not None:
        body_summary = ability_external_target_body_ledger["summary"]
        result["sources"]["ability_external_target_body_ledger"] = _source(
            ability_external_target_body_ledger_path)
        result["closed_bounded"].append({
            "claim": "Ability external target native body classification",
            "targets": body_summary["targets"],
            "exact_pdata_bodies": body_summary["exact_pdata_bodies"],
            "unidentified_targets": body_summary["unidentified_targets"],
            "unidentified_callsites": body_summary["unidentified_callsites"],
            "unidentified_callsites_in_direct_call_then_trap_stubs":
                body_summary["unidentified_callsites_in_direct_call_then_trap_stubs"],
            "body_class_counts": body_summary["body_class_counts"],
            "nested_direct_calls_with_catalog_identity":
                body_summary["nested_direct_calls_with_catalog_identity"],
            "scope": ("exact GameAssembly PDATA bodies and mechanical native shapes; "
                      "body classes are not promoted to semantic names"),
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "unidentified_direct_targets": body_summary["unidentified_targets"],
                    "unidentified_direct_callsites": body_summary["unidentified_callsites"],
                    "mechanically_bounded_call_then_trap_callsites":
                        body_summary[
                            "unidentified_callsites_in_direct_call_then_trap_stubs"],
                })
                row["reason"] = (
                    "all external direct targets now have an exact native boundary/body account; "
                    "unidentified multi-call bodies still require source-backed ownership or "
                    "bounded dependency analysis, while mechanical trap-stub shapes remain unnamed")
        result["next_work"] = [
            "prioritize the remaining unidentified multi-call bodies by Remielle asset occurrence and exact downstream catalog joins",
            "resolve the 21 initialized-slot candidates only after static owner and registration evidence is exhausted",
            "prepare runtime observation only for dynamic receiver/slot identity that cannot be recovered from native metadata",
        ]
        result["runtime_required_now"] = False
    if ability_external_target_arena_join is not None:
        arena_summary = ability_external_target_arena_join["summary"]
        result["sources"]["ability_external_target_arena_join"] = _source(
            ability_external_target_arena_join_path)
        result["closed_bounded"].append({
            "claim": "Ability external target preserved-arena ownership candidates",
            **arena_summary,
            "scope": ("exact preserved code pointer, class self-label and owning method-array "
                      "membership; method ordinal is not promoted to a method name"),
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "external_targets_with_arena_method_candidate":
                        arena_summary["targets_with_arena_method_candidate"],
                    "external_targets_with_exact_arena_class_identity":
                        arena_summary["targets_with_exact_class_list_identity"],
                    "external_targets_absent_from_preserved_arena":
                        arena_summary["targets_not_present_in_preserved_arena"],
                })
                row["reason"] = (
                    "the preserved loading-phase arena adds bounded class/ordinal ownership "
                    "candidates for five direct targets, but supplies no authoritative method "
                    "name; remaining identities need registration evidence or runtime dynamic "
                    "receiver/slot values")
        result["next_work"] = [
            "finish declared receiver-field and vtable-slot contracts for the 38 dynamic dispatch callsites",
            "compile one low-overhead unit that snapshots 21 initialized slots and records only executed dynamic dispatch sites",
            "do not synthesize semantic method names from arena ordinals or base-class null vtable slots",
        ]
        result["runtime_required_now"] = False
    if (ability_dynamic_dispatch_plan is not None
            and ability_dynamic_dispatch_runtime is None):
        result["sources"]["ability_dynamic_dispatch_plan"] = _source(
            ability_dynamic_dispatch_plan_path)
        result["next_capture"] = {
            "plan_id": "ability-dynamic-dispatch-v1",
            "source_plan": ability_dynamic_dispatch_plan["plan"],
            "qualification": ability_dynamic_dispatch_plan["qualification"],
            "initialized_slots": ability_dynamic_dispatch_plan[
                "unresolved_initialized_slots"],
            "logical_dynamic_callsites": ability_dynamic_dispatch_plan[
                "dynamic_callsites"],
            "physical_dynamic_probe_sites": ability_dynamic_dispatch_plan[
                "physical_dynamic_probe_sites"],
            "qualification_sites": ability_dynamic_dispatch_plan[
                "qualification_sites"],
            "near_only_sites": ability_dynamic_dispatch_plan[
                "near_only_qualification_sites"],
            "formal_runtime_rounds": 1,
            "purpose": ("read the 21 process-initialized direct targets once and record exact "
                        "dynamic receiver/class/target identities only at executed callsites"),
        }
        result["next_work"] = [
            "qualify all 36 physical sites once in the target process before entering trial",
            "bind the returned patch contracts into one process-bound entry-only instruction plan without rebuilding the DLL",
            "run one broad marked trial session; unexecuted dynamic sites remain explicit NOT_OBSERVED rather than receiving invented identities",
        ]
        result["runtime_required_now"] = True
    if ability_dynamic_dispatch_runtime is not None:
        runtime_summary = ability_dynamic_dispatch_runtime["summary"]
        method_summary = ability_dynamic_dispatch_method_join["summary"]
        slot_summary = ability_initialized_slot_import_join["summary"]
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "runtime_observed_dynamic_targets": method_summary[
                        "observed_game_target_rvas"],
                    "runtime_targets_with_exact_catalog_method": method_summary[
                        "exact_catalogued_method_targets"],
                    "runtime_targets_without_catalog_method": method_summary[
                        "uncatalogued_method_targets"],
                    "non_import_initialized_slots_without_owner": slot_summary[
                        "non_import_initialized_slots"],
                    "dynamic_probe_sites_not_observed": runtime_summary[
                        "unobserved_dynamic_probe_sites"],
                })
                row["reason"] = (
                    "the clean runtime generation supplies exact values for all initialized "
                    "slots and exact receiver/class/target evidence for 20 physical dynamic "
                    "sites; remaining work is bounded static ownership and method-catalog "
                    "recovery, plus static relevance analysis of 15 unobserved sites")
        result.pop("next_capture", None)
        result["next_work"] = [
            "map the 9 uncatalogued observed GameAssembly target RVAs using authoritative method/type and native-body evidence",
            "resolve the 18 non-PE-import initialized slot owners from static registration and preserved arena evidence without guessing a module",
            "statically assess the 15 unobserved dynamic sites for Remielle relevance before proposing any further runtime capture",
        ]
        result["runtime_required_now"] = False
    if ability_dynamic_dispatch_authoritative_join is not None:
        authoritative_summary = ability_dynamic_dispatch_authoritative_join["summary"]
        consumer_summary = ability_initialized_slot_consumer_join["summary"]
        scan_summary = ability_dynamic_target_multipass_scan["summary"]
        body_summary = ability_dynamic_target_body_ledger["summary"]
        relevance_summary = ability_unobserved_static_relevance["summary"]
        result["sources"].update({
            "ability_dynamic_dispatch_authoritative_join": _source(
                ability_dynamic_dispatch_authoritative_join_path),
            "ability_initialized_slot_consumer_join": _source(
                ability_initialized_slot_consumer_join_path),
            "ability_dynamic_target_multipass_scan": _source(
                ability_dynamic_target_multipass_scan_path),
            "ability_dynamic_target_body_ledger": _source(
                ability_dynamic_target_body_ledger_path),
            "ability_unobserved_static_relevance": _source(
                ability_unobserved_static_relevance_path),
        })
        result["closed_bounded"].extend([
            {
                "claim": "runtime dynamic targets joined to authoritative method harvests",
                "observed_game_target_rvas": authoritative_summary["observed_game_target_rvas"],
                "exact_catalogued_method_targets": authoritative_summary[
                    "exact_catalogued_method_targets"],
                "newly_catalogued_method_targets": authoritative_summary[
                    "newly_catalogued_method_targets"],
                "scope": "exact RVA joins only; receiver class and declaring class remain separate",
            },
            {
                "claim": "initialized dynamic slots have exact static Ability consumers",
                "initialized_slots": consumer_summary["initialized_slots"],
                "slots_with_static_consumers": consumer_summary["slots_with_static_consumers"],
                "static_consumer_callsites": consumer_summary["static_consumer_callsites"],
                "scope": "decoded exact callsites; initializer ownership remains separate",
            },
            {
                "claim": "uncatalogued dynamic target MethodInfo owner scan",
                "target_rvas": scan_summary["target_rvas"],
                "covered_class_list_types": scan_summary["covered_types"],
                "exact_positive_matches": scan_summary["exact_positive_matches"],
                "scope": "complete private-load scan of the 9121 harvested class-list type indexes",
            },
            {
                "claim": "uncatalogued dynamic target native bodies",
                "exact_pdata_bodies": body_summary["exact_pdata_bodies"],
                "fully_decoded_bodies": body_summary["fully_decoded_bodies"],
                "exact_fast_path_field_loads": body_summary["exact_fast_path_field_loads"],
                "scope": "mechanical native body evidence without semantic names",
            },
            {
                "claim": "unobserved dynamic sites have Remielle Origin static relevance",
                "callsites": relevance_summary["represented_unobserved_callsites"],
                "caller_types": relevance_summary["unique_caller_types"],
                "classification_counts": relevance_summary["classification_counts"],
                "scope": "asset occurrence proves static relevance, not execution or a player-action predicate",
            },
        ])
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "runtime_observed_dynamic_targets": authoritative_summary[
                        "observed_game_target_rvas"],
                    "runtime_targets_with_exact_catalog_method": authoritative_summary[
                        "exact_catalogued_method_targets"],
                    "runtime_targets_without_catalog_method": authoritative_summary[
                        "uncatalogued_method_targets"],
                    "uncatalogued_targets_with_complete_native_body": body_summary[
                        "fully_decoded_bodies"],
                    "method_owner_scan_covered_types": scan_summary["covered_types"],
                    "non_import_initialized_slots_with_static_consumers": consumer_summary[
                        "non_import_slots_with_static_consumers"],
                    "non_import_initialized_slots_without_initializer_owner": consumer_summary[
                        "non_import_slots_with_unresolved_initializer"],
                    "runtime_conditional_unobserved_callsites": relevance_summary[
                        "classification_counts"]["RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH"],
                })
                row["reason"] = (
                    "13 of 18 observed dynamic targets now have exact harvested method identities; "
                    "the other five have complete native bodies and a complete negative MethodInfo "
                    "owner scan within 9121 types. All 18 non-import slots have exact consumers but "
                    "their initializer owners remain unresolved; 14 unobserved Remielle-relevant "
                    "conditional paths require static branch analysis before another capture")
        result["next_work"] = [
            "decode predecessor branches and local dataflow for the 14 Remielle-relevant unobserved runtime paths",
            "trace writes and registration paths for the 18 non-import initialized slots from their 58 exact static consumers",
            "request another runtime session only for a statically identified reachable condition or initializer identity that cannot be recovered offline",
        ]
        result["runtime_required_now"] = False
    if ability_unobserved_branch_ledger is not None:
        branch_summary = ability_unobserved_branch_ledger["summary"]
        predicate_summary = ability_unobserved_predicate_join["summary"]
        module_summary = ability_initialized_slot_module_join["summary"]
        xref_summary = ability_initialized_slot_pdata_xrefs["summary"]
        storage_summary = ability_initialized_slot_storage_ledger["summary"]
        result["sources"].update({
            "ability_unobserved_branch_ledger": _source(
                ability_unobserved_branch_ledger_path),
            "ability_unobserved_predicate_join": _source(
                ability_unobserved_predicate_join_path),
            "ability_initialized_slot_module_join": _source(
                ability_initialized_slot_module_join_path),
            "ability_initialized_slot_pdata_xrefs": _source(
                ability_initialized_slot_pdata_xrefs_path),
            "ability_initialized_slot_storage_ledger": _source(
                ability_initialized_slot_storage_ledger_path),
        })
        result["closed_bounded"].extend([
            {
                "claim": "unobserved Ability callsites exact mechanical branch frontier",
                "runtime_conditional_sites": branch_summary["runtime_conditional_sites"],
                "reachable_nonmandatory_sites": branch_summary[
                    "sites_reachable_but_not_mandatory_in_complete_mechanical_cfg"],
                "sites_with_strong_dominating_gate": branch_summary[
                    "sites_with_mechanical_gating_branch"],
                "sites_with_outcome_sensitive_branch": branch_summary[
                    "sites_with_outcome_sensitive_branch"],
                "unresolved_indirect_control": branch_summary[
                    "sites_with_remaining_unresolved_indirect_control"],
                "scope": "exact native CFG and branch outcomes; no gameplay condition names",
            },
            {
                "claim": "unobserved Ability branch input candidate ledger",
                "sites": predicate_summary["sites"],
                "strong_gate_selections": predicate_summary["selection_counts"][
                    "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE"],
                "non_dominating_route_selections": predicate_summary["selection_counts"][
                    "NEAREST_PRECEDING_NON_DOMINATING_OUTCOME_SENSITIVE_BRANCH"],
                "sites_with_numeric_field_offset_candidates": predicate_summary[
                    "sites_with_harvested_field_offset_candidates"],
                "exact_field_identities_assigned": 0,
                "semantic_gameplay_predicates_assigned": 0,
                "scope": "machine predicate shapes and offset candidates only",
            },
            {
                "claim": "initialized Ability slot runtime target module and RVA identity",
                "non_import_slots": module_summary["non_import_slots"],
                "module": module_summary["selected_module"],
                "exact_module_pdata_targets": module_summary[
                    "slots_with_exact_module_pdata_target"],
                "unique_target_rvas": module_summary["unique_exact_module_pdata_targets"],
                "scope": "unique local module/base translation; no function semantic names",
            },
            {
                "claim": "initialized Ability slot GameAssembly storage and xref boundary",
                "virtual_zero_fill_slots": storage_summary[
                    "storage_counts"]["VIRTUAL_ZERO_FILL_TAIL"],
                "slots_without_file_initial_value": storage_summary[
                    "slots_without_file_backed_initial_value"],
                "exact_decoded_pdata_references": xref_summary[
                    "exact_rip_relative_references"],
                "write_references_in_decoded_pdata": xref_summary[
                    "slots_with_pdata_write_reference"],
                "scope": "supplied PE section table and decoded GameAssembly PDATA bodies only",
            },
        ])
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "unobserved_sites_with_exact_mechanical_cfg": branch_summary[
                        "sites_with_exact_caller_body"],
                    "unobserved_sites_with_strong_dominating_gate": branch_summary[
                        "sites_with_mechanical_gating_branch"],
                    "unobserved_sites_with_only_nondominating_selected_route_guard":
                        predicate_summary["selection_counts"][
                            "NEAREST_PRECEDING_NON_DOMINATING_OUTCOME_SENSITIVE_BRANCH"],
                    "non_import_slots_with_exact_runtime_target_module_rva": module_summary[
                        "slots_with_exact_module_pdata_target"],
                    "non_import_slots_in_virtual_zero_fill_storage": storage_summary[
                        "storage_counts"]["VIRTUAL_ZERO_FILL_TAIL"],
                    "gameassembly_pdata_slot_write_references": xref_summary[
                        "slots_with_pdata_write_reference"],
                })
                row["reason"] = (
                    "all 14 unobserved Remielle-relevant conditional sites now have complete "
                    "mechanical CFGs and outcome-sensitive branch frontiers; 10 have strong "
                    "dominating gates, while four retain only non-dominating route evidence and "
                    "no gameplay predicate is guessed. All 18 non-import slots are zero-fill "
                    "GameAssembly storage, resolve at runtime to 17 exact UnityPlayer PDATA RVAs, "
                    "and have no write reference in decoded GameAssembly PDATA bodies; exact "
                    "initializer ownership remains an infrastructure provenance gap")
        result["next_work"] = [
            "prove base-object identity and serialized-field provenance for the 10 strongly gated unobserved Ability sites where static dataflow permits it",
            "classify the four non-dominating route-guard sites without promoting shared native guard boilerplate to gameplay semantics",
            "treat the 18 slot initializer writers as loader/infrastructure provenance unless a controller-semantic dependency is found",
            "request another runtime session only for a concrete branch input or object identity that survives the remaining static joins",
        ]
        result["runtime_required_now"] = False
    if ability_unobserved_base_identity_join is not None:
        base_summary = ability_unobserved_base_identity_join["summary"]
        result["sources"]["ability_unobserved_base_identity_join"] = _source(
            ability_unobserved_base_identity_join_path)
        result["closed_bounded"].append({
            "claim": "unobserved Ability branch base-object and field identity frontier",
            "sites": base_summary["sites"],
            "sites_with_stable_nonvolatile_this_alias": base_summary[
                "sites_with_stable_nonvolatile_this_alias"],
            "sites_with_exact_field_access_in_selected_window": base_summary[
                "sites_with_exact_field_access_in_selected_window"],
            "selected_test_values_with_exact_object_provenance": base_summary[
                "selected_test_values_with_exact_object_provenance"],
            "scope": "Windows x64 nonvolatile this aliases and exact harvested class-field offsets",
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "unobserved_sites_with_stable_this_alias": base_summary[
                        "sites_with_stable_nonvolatile_this_alias"],
                    "unobserved_sites_with_exact_selected_window_field": base_summary[
                        "sites_with_exact_field_access_in_selected_window"],
                    "unobserved_selected_test_values_with_exact_object_provenance":
                        base_summary["selected_test_values_with_exact_object_provenance"],
                })
                row["reason"] += (
                    "; exact local dataflow now proves stable method-this identity for 12 sites, "
                    "exact selected-window fields for five, and the final tested object source for "
                    "two; the remaining values require runtime call-site state or deeper callee/stack provenance")
        result["next_work"] = [
            "compile one merged read-only branch-input plan for the unresolved stack, return-value, and secondary-object predicates",
            "include the two statically exact tested-object sites as controls rather than asking the player to target guessed moves",
            "keep the four non-dominating route-guard sites as execution-coverage probes, not gameplay-condition probes",
            "validate the plan offline and request one runtime session only after all reads and bounds are precompiled",
        ]
        result["runtime_required_now"] = False
    if ability_unobserved_branch_runtime_plan is not None:
        plan_summary = ability_unobserved_branch_runtime_plan
        result["sources"]["ability_unobserved_branch_runtime_plan"] = _source(
            ability_unobserved_branch_runtime_plan_path)
        result["closed_bounded"].append({
            "claim": "merged read-only Ability branch-input capture unit",
            "logical_source_sites": plan_summary["logical_source_sites"],
            "physical_predicate_sites": plan_summary["physical_predicate_sites"],
            "near_only_qualification_sites": plan_summary["near_only_sites"],
            "exact_tested_object_controls": plan_summary[
                "exact_tested_object_controls"],
            "scope": "pre-instruction raw values only; no gameplay predicate assigned",
        })
        for row in result["offline_open"]:
            if row["claim"] == "Ability executor semantic and external dependency audit":
                row.update({
                    "branch_input_runtime_unit_prepared": True,
                    "branch_input_logical_sites": plan_summary["logical_source_sites"],
                    "branch_input_physical_sites": plan_summary["physical_predicate_sites"],
                })
                row["reason"] += (
                    "; one merged near-only read-only runtime unit now covers all 14 logical "
                    "branch inputs at 13 physical predicate instructions, including two exact "
                    "field-chain controls; activation still requires target-process qualification")
        result["next_work"] = [
            "start one target process and qualify all 13 near-only predicate sites without publishing a capture generation",
            "apply the target-bound qualified plan in the same process and retain all raw zero/nonzero predicate inputs",
            "use checkpoints for broad action phases; no guessed one-move-to-one-site mapping is required",
            "stop cleanly, verify coverage and loss accounting, then join observed values back to the 14 native source paths",
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
    parser.add_argument("--field-lifecycle", type=Path)
    parser.add_argument("--field-runtime-join", type=Path)
    parser.add_argument("--caller-stage-profile", type=Path)
    parser.add_argument("--caller-static-decode", type=Path)
    parser.add_argument("--caller-ghidra-join", type=Path)
    parser.add_argument("--static-gap-analysis", type=Path)
    parser.add_argument("--runtime-closure-acceptance", type=Path)
    parser.add_argument("--runtime-closure-caller-join", type=Path)
    parser.add_argument("--task-context-static-join", type=Path)
    parser.add_argument("--task-receiver-join", type=Path)
    parser.add_argument("--task-ancestor-join", type=Path)
    parser.add_argument("--int-comparison-enum", type=Path)
    parser.add_argument("--task-reset-audit", type=Path)
    parser.add_argument("--exact-closure-plan", type=Path)
    parser.add_argument("--exact-closure-runtime-analysis", type=Path)
    parser.add_argument("--nested-condition-runtime-analysis", type=Path)
    parser.add_argument("--selector-join", type=Path)
    parser.add_argument("--upstream-invoker-join", type=Path)
    parser.add_argument("--final-runtime-analysis", type=Path)
    parser.add_argument("--final-identity-join", type=Path)
    parser.add_argument("--animator-stage-static-join", type=Path)
    parser.add_argument("--legacy-animator-stage-instance-join", type=Path)
    parser.add_argument("--ability-executor-coverage", type=Path)
    parser.add_argument("--action-window-attribution", type=Path)
    parser.add_argument("--ability-dependency-frontier", type=Path)
    parser.add_argument("--ability-indirect-call-join", type=Path)
    parser.add_argument("--ability-external-target-body-ledger", type=Path)
    parser.add_argument("--ability-external-target-arena-join", type=Path)
    parser.add_argument("--ability-dynamic-dispatch-plan", type=Path)
    parser.add_argument("--ability-dynamic-dispatch-runtime", type=Path)
    parser.add_argument("--ability-dynamic-dispatch-method-join", type=Path)
    parser.add_argument("--ability-initialized-slot-import-join", type=Path)
    parser.add_argument("--ability-dynamic-dispatch-authoritative-join", type=Path)
    parser.add_argument("--ability-initialized-slot-consumer-join", type=Path)
    parser.add_argument("--ability-dynamic-target-multipass-scan", type=Path)
    parser.add_argument("--ability-dynamic-target-body-ledger", type=Path)
    parser.add_argument("--ability-unobserved-static-relevance", type=Path)
    parser.add_argument("--ability-unobserved-branch-ledger", type=Path)
    parser.add_argument("--ability-unobserved-predicate-join", type=Path)
    parser.add_argument("--ability-initialized-slot-module-join", type=Path)
    parser.add_argument("--ability-initialized-slot-pdata-xrefs", type=Path)
    parser.add_argument("--ability-initialized-slot-storage-ledger", type=Path)
    parser.add_argument("--ability-unobserved-base-identity-join", type=Path)
    parser.add_argument("--ability-unobserved-branch-runtime-plan", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.role_gap.resolve(), args.animator_acceptance.resolve(), args.animator_join.resolve(),
        args.api_usage.resolve(), args.controller_caller_join.resolve(), args.occurrence_trace.resolve(),
        args.dispatch_role.resolve(), args.out.resolve(),
        args.causal_frontier_acceptance.resolve() if args.causal_frontier_acceptance else None,
        args.next_plan.resolve() if args.next_plan else None,
        args.field_lifecycle.resolve() if args.field_lifecycle else None,
        args.field_runtime_join.resolve() if args.field_runtime_join else None,
        args.caller_stage_profile.resolve() if args.caller_stage_profile else None,
        args.caller_static_decode.resolve() if args.caller_static_decode else None,
        args.caller_ghidra_join.resolve() if args.caller_ghidra_join else None,
        args.static_gap_analysis.resolve() if args.static_gap_analysis else None,
        args.runtime_closure_acceptance.resolve() if args.runtime_closure_acceptance else None,
        args.runtime_closure_caller_join.resolve() if args.runtime_closure_caller_join else None,
        args.task_context_static_join.resolve() if args.task_context_static_join else None,
        args.task_receiver_join.resolve() if args.task_receiver_join else None,
        args.task_ancestor_join.resolve() if args.task_ancestor_join else None,
        args.int_comparison_enum.resolve() if args.int_comparison_enum else None,
        args.task_reset_audit.resolve() if args.task_reset_audit else None,
        args.exact_closure_plan.resolve() if args.exact_closure_plan else None,
        args.exact_closure_runtime_analysis.resolve() if args.exact_closure_runtime_analysis else None,
        args.nested_condition_runtime_analysis.resolve() if args.nested_condition_runtime_analysis else None,
        args.selector_join.resolve() if args.selector_join else None,
        args.upstream_invoker_join.resolve() if args.upstream_invoker_join else None,
        args.final_runtime_analysis.resolve() if args.final_runtime_analysis else None,
        args.final_identity_join.resolve() if args.final_identity_join else None,
        args.animator_stage_static_join.resolve() if args.animator_stage_static_join else None,
        (args.legacy_animator_stage_instance_join.resolve()
         if args.legacy_animator_stage_instance_join else None),
        args.ability_executor_coverage.resolve() if args.ability_executor_coverage else None,
        args.action_window_attribution.resolve() if args.action_window_attribution else None,
        args.ability_dependency_frontier.resolve() if args.ability_dependency_frontier else None,
        args.ability_indirect_call_join.resolve() if args.ability_indirect_call_join else None,
        (args.ability_external_target_body_ledger.resolve()
         if args.ability_external_target_body_ledger else None),
        (args.ability_external_target_arena_join.resolve()
         if args.ability_external_target_arena_join else None),
        (args.ability_dynamic_dispatch_plan.resolve()
         if args.ability_dynamic_dispatch_plan else None),
        (args.ability_dynamic_dispatch_runtime.resolve()
         if args.ability_dynamic_dispatch_runtime else None),
        (args.ability_dynamic_dispatch_method_join.resolve()
         if args.ability_dynamic_dispatch_method_join else None),
        (args.ability_initialized_slot_import_join.resolve()
         if args.ability_initialized_slot_import_join else None),
        (args.ability_dynamic_dispatch_authoritative_join.resolve()
         if args.ability_dynamic_dispatch_authoritative_join else None),
        (args.ability_initialized_slot_consumer_join.resolve()
         if args.ability_initialized_slot_consumer_join else None),
        (args.ability_dynamic_target_multipass_scan.resolve()
         if args.ability_dynamic_target_multipass_scan else None),
        (args.ability_dynamic_target_body_ledger.resolve()
         if args.ability_dynamic_target_body_ledger else None),
        (args.ability_unobserved_static_relevance.resolve()
         if args.ability_unobserved_static_relevance else None),
        (args.ability_unobserved_branch_ledger.resolve()
         if args.ability_unobserved_branch_ledger else None),
        (args.ability_unobserved_predicate_join.resolve()
         if args.ability_unobserved_predicate_join else None),
        (args.ability_initialized_slot_module_join.resolve()
         if args.ability_initialized_slot_module_join else None),
        (args.ability_initialized_slot_pdata_xrefs.resolve()
         if args.ability_initialized_slot_pdata_xrefs else None),
        (args.ability_initialized_slot_storage_ledger.resolve()
         if args.ability_initialized_slot_storage_ledger else None),
        (args.ability_unobserved_base_identity_join.resolve()
         if args.ability_unobserved_base_identity_join else None),
        (args.ability_unobserved_branch_runtime_plan.resolve()
         if args.ability_unobserved_branch_runtime_plan else None))
