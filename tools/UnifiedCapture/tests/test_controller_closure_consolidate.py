from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller_closure_consolidate import run
from uc.model import canonical, file_hash


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_supersedes_closed_api_gap_without_claiming_live_invocation(tmp_path: Path) -> None:
    role = {"summary": {"wrapper_observed": 4, "wrapper_total": 5,
        "native_implementation_observed": 0, "native_implementation_total": 5}}
    animator = {"checks": {"all_logical_edges_static_verified": True,
        "logical_edge_count": 17, "catalog_anchored_edge_count": 1}}
    acceptance = {"accepted": True, "game_runtime_verified": True,
                  "points": [{"status": "OBSERVED_LOSSLESS"}] * 13}
    api = {"scope": {"selectedEncryptedApiTargetsClosed": True,
        "selectedBridgeInvocationAbiClosed": True}, "invoke": {"unitySlotRva": 1,
        "gameTargetRva": 2, "invokerRva": 3, "bridgeCodeRva": 4,
        "argumentRegisters": ["RCX", "RDX", "R8"], "liveInvocationObserved": False}}
    callers = {"summary": {"unresolved_rows": 12}}
    occurrence = {"checks": {"scanned_occurrence_count": 1, "ok": True},
                  "occurrences": [{"ability": "AirCombat"}]}
    dispatch = {"checks": {"ok": True}, "classifications": [
        {"method": "HCB", "derived_role": "wrapper"},
        {"method": "BHCI", "derived_role": "nativeImplementation"}]}
    result = run(_write(tmp_path / "role.json", role), _write(tmp_path / "acceptance.json", acceptance),
                 _write(tmp_path / "anim.json", animator), _write(tmp_path / "api.json", api),
                 _write(tmp_path / "callers.json", callers), _write(tmp_path / "occ.json", occurrence),
                 _write(tmp_path / "dispatch.json", dispatch), tmp_path / "out")
    assert any("final target" in row["statement"] for row in result["superseded_gap_statements"])
    assert any("live selected Unity bridge" in row["claim"] for row in result["runtime_open"])
    assert result["runtime_required_now"] is False

    frontier = {"schema": "uc.entry-evidence-acceptance.v2", "accepted": False,
                "points": [{"point": "hot", "status": "UNKNOWN"},
                           {"point": "covered", "status": "OBSERVED"}]}
    next_plan = {"schema": "uc.capture-plan.v2", "plan_id": "next", "plan_revision": 2,
                 "points": [{"id": "hot", "retention": {
                     "mode": "first_per_entry_return_address", "max_keys": 16}}]}
    updated = run(tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
                  tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
                  tmp_path / "dispatch.json", tmp_path / "out2",
                  _write(tmp_path / "frontier.json", frontier),
                  _write(tmp_path / "next.json", next_plan))
    assert updated["runtime_required_now"] is True
    assert updated["next_capture"]["aggregate_caller_retention_points"] == ["hot"]
    assert "1 lossy points" in updated["runtime_observation_state"]["global_acceptance_reason"]

    accepted_frontier = {"schema": "uc.entry-evidence-acceptance.v2", "accepted": True,
        "points": [{"point": "GameAssembly.animator-fixed-update-bridge@0x4/entry",
                    "status": "OBSERVED", "event_count": 27}]}
    field = {"schema": "uc.controller-field-lifecycle-analysis.v1", "summary": {
        "parameter_task_start_update_same_address": 8,
        "parameter_task_address_candidates": 9,
        "parameter_task_reset_observed": 0,
        "ecs_complete_lifecycles": 2,
        "ecs_system_address_candidates": 4,
        "ecs_open_end_boundary": 1,
    }}
    closed = run(tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
                 tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
                 tmp_path / "dispatch.json", tmp_path / "out3",
                 _write(tmp_path / "accepted-frontier.json", accepted_frontier), None,
                 _write(tmp_path / "field.json", field))
    assert closed["runtime_required_now"] is False
    assert "globally accepted" in closed["runtime_observation_state"]["global_acceptance_reason"]
    assert any(row["claim"] == "live selected Animator fixed-update bridge code entry"
               for row in closed["closed_bounded"])
    assert not any(row["claim"] == "live selected Unity bridge invocation for the current game instance"
                   for row in closed["runtime_open"])

    runtime_join = {"schema": "uc.entry-runtime-static-join.v1", "checks": {
        "invalid_static_join_count": 0, "unresolved_caller_evidence_count": 0,
        "caller_evidence_count": 20, "pdata_owned_caller_evidence_count": 20,
        "logical_edge_count": 4, "catalog_anchored_edge_count": 2,
        "static_matched_caller_evidence_count": 5,
        "catalog_matched_caller_evidence_count": 3,
        "unmatched_caller_evidence_count": 12,
    }}
    stage = {"schema": "uc.retained-caller-stage-profile.v1", "summary": {
        "retained_caller_keys": 20, "single_action_window_callers": 6,
        "single_action_window_priority_candidates": 3,
    }}
    joined = run(tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
                 tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
                 tmp_path / "dispatch.json", tmp_path / "out4",
                 tmp_path / "accepted-frontier.json", None, tmp_path / "field.json",
                 _write(tmp_path / "runtime-join.json", runtime_join),
                 _write(tmp_path / "stage.json", stage))
    assert joined["offline_open"][0]["unmatched_rows"] == 12
    assert joined["offline_open"][0]["stage_priority_candidates"] == 3
    assert any(row["claim"] == "retained caller action-window profile"
               for row in joined["closed_bounded"])

    decode = {"schema": "uc.caller-candidate-static-decode.v1", "summary": {
        "priority_callsites": 3, "direct_target_verified_callsites": 3,
        "runtime_functions": 2, "fully_decoded_functions": 2}}
    ghidra = {"schema": "uc.caller-candidate-ghidra-join.v1", "summary": {
        "functions": 2, "instruction_agreement_functions": 2,
        "capstone_instructions": 20, "ghidra_instructions": 20,
        "external_incoming_references": 1}}
    static_gap = {"schema": "uc.controller-static-gap-analysis.v1", "checks": {
        "reset_implementation_count": 4, "all_reset_implementations_source_verified": True,
        "all_reset_entries_not_observed": True,
        "parallel_job_static_chain_source_verified": True,
        "parallel_job_wrapper_not_observed": True},
        "parallel_job_dispatch": {
            "concrete_execute_thunk": {"rva": 1}, "generated_wrapper": {"rva": 2},
            "shared_body": {"rva": 3, "consumer_rva": 4}}}
    static_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out5", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        _write(tmp_path / "decode.json", decode), _write(tmp_path / "ghidra.json", ghidra),
        _write(tmp_path / "static-gap.json", static_gap))
    assert static_closed["runtime_required_now"] is True
    assert any(row["claim"] == "selected parameter task OnReset implementation semantics"
               for row in static_closed["closed_bounded"])
    reset_gap = next(row for row in static_closed["runtime_open"]
                     if row["claim"] == "task reset lifecycle for selected parameter tasks")
    assert "implementation is closed statically" in reset_gap["reason"]

    closure_acceptance = {"schema": "uc.entry-evidence-acceptance.v2",
        "accepted": True, "game_runtime_verified": True, "points": [
            {"point": "ParallelForJobStruct<IKNHGFBHLLK>.Execute@0x1/entry",
             "status": "NOT_OBSERVED_IN_COVERED_WINDOW"},
            {"point": "IKNHGFBHLLK.shared-execute-body@0x2/entry",
             "status": "NOT_OBSERVED_IN_COVERED_WINDOW"},
            {"point": "ODKPBBAJAEG.KBPGJAPPBLI@0x3/entry",
             "status": "NOT_OBSERVED_IN_COVERED_WINDOW"},
        ]}
    closure_callers = {"schema": "uc.controller-runtime-caller-join.v1",
        "summary": {"source_identified_rows": 8, "runtime_edges": 14},
        "runtime_callsite_rows": [{
            "callee_point": "GameAssembly.animator-fixed-update-bridge@0x4/entry",
            "caller_runtime_function": {"begin_rva": 3, "end_rva": 10},
            "callsite_rva": 7, "observation_count": 12,
        }]}
    task_join = {"schema": "uc.task-context-static-join.v1", "summary": {
        "ambiguous_static_tree_matches": 0}, "behavior_trees": [{
            "behavior_tree_address": 0x1000,
            "identity_status": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
            "observed_task_signature": [{"runtime_task_index": 7, "native_type_index": 3}],
            "candidate_static_trees": [{
                "root_tree": "Behavior_Avatar_RemielleOrigin_Decision"}],
        }]}
    runtime_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out6", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        _write(tmp_path / "closure-acceptance.json", closure_acceptance),
        _write(tmp_path / "closure-callers.json", closure_callers),
        _write(tmp_path / "task-join.json", task_join))
    assert runtime_closed["runtime_required_now"] is False
    assert any(row["claim"] == "live Animator invoker to selected bridge same-invocation execution"
               for row in runtime_closed["closed_bounded"])
    tree_claim = next(row for row in runtime_closed["closed_bounded"]
                      if row["claim"] == "Remielle Origin expanded BehaviorTree runtime candidate")
    assert tree_claim["matched_task_signatures"] == 1
    upstream_gap = next(row for row in runtime_closed["runtime_open"]
                        if row["claim"] ==
                        "selected Unity API target to Animator invoker same-invocation causality")
    assert "invoker to bridge is now observed" in upstream_gap["reason"]

    receiver_join = {"schema": "uc.task-receiver-runtime-join.v1", "summary": {
        "matched_task_contexts": 25, "direct_animator_tasks": 22,
        "component_animator_tasks": 3, "unique_direct_animator_addresses": 1,
        "unique_animator_component_addresses": 1, "unique_trigger_owner_entities": 1,
        "direct_animator_address": 0x4000, "animator_component_address": 0x5000,
        "trigger_owner_entity": 0x6000}}
    receiver_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out7", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", _write(tmp_path / "receiver-join.json", receiver_join))
    assert receiver_closed["runtime_required_now"] is False
    assert any(row["claim"] == "Remielle BehaviorTree parameter tasks to runtime receivers"
               for row in receiver_closed["closed_bounded"])
    stage_gap = next(row for row in receiver_closed["runtime_open"]
                     if row["claim"] == "same-instance Animator stage to parameter-consumer causality")
    assert "task to receiver is closed" in stage_gap["reason"]

    ancestor_join = {"schema": "uc.task-ancestor-static-join.v1", "summary": {
        "joined_task_signatures": 25, "serialized_subtrees": 2,
        "unique_ancestor_chains": 11, "conditional_evaluator_nodes": 5,
        "random_weight_nodes": 2}, "task_ancestor_rows": [{
            "ancestor_conditions": [{
                "tree": f"tree-{index}", "task_index": index,
                "conditional_task_type": "IntComparison",
                "integer1_shared_name": "Int_Test",
                "integer2_constant_raw": index,
                "operation_raw": 2,
            }]
        } for index in range(5)]}
    ancestor_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out8", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", tmp_path / "receiver-join.json",
        _write(tmp_path / "ancestor-join.json", ancestor_join))
    ancestor_claim = next(row for row in ancestor_closed["closed_bounded"]
                          if row["claim"] ==
                          "observed Remielle tasks to serialized ancestor branches")
    assert len(ancestor_claim["conditions"]) == 5
    assert ancestor_claim["conditions"][0]["operation_raw"] == 2
    assert ancestor_closed["runtime_required_now"] is False

    enum_decode = {"schema": "uc.int-comparison-enum-decode.v1",
        "operation_field_offset": 0x60,
        "mappings": [{"raw_value": index, "enum_member": name,
                      "predicate_instruction": instruction,
                      "native_predicate": predicate}
                     for index, (name, instruction, predicate) in enumerate([
                         ("LessThan", "setl", "signed_less_than"),
                         ("LessThanOrEqualTo", "setle", "signed_less_than_or_equal"),
                         ("EqualTo", "sete", "equal"),
                         ("NotEqualTo", "setne", "not_equal"),
                         ("GreaterThanOrEqualTo", "setge", "signed_greater_than_or_equal"),
                         ("GreaterThan", "setg", "signed_greater_than")])],
        "selected_runtime_value": {"raw_value": 2, "enum_member": "EqualTo",
                                   "predicate_instruction": "sete",
                                   "native_predicate": "equal"}}
    enum_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out9", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", tmp_path / "receiver-join.json",
        tmp_path / "ancestor-join.json", _write(tmp_path / "enum.json", enum_decode))
    enum_claim = next(row for row in enum_closed["closed_bounded"]
                      if row["claim"] == "IntComparison serialized operation numeric semantics")
    assert enum_claim["selected_runtime_value"]["enum_member"] == "EqualTo"

    reset_audit = {"schema": "uc.task-reset-dispatch-audit.v1", "coverage": {
        "behavior_manager_methods": 99, "unique_pdata_functions": 91,
        "pdata_less_bounded_heads": 8, "all_pdata_functions_completely_decoded": True},
        "dispatch": {"OnStart": [{}], "OnEnd": [{}], "OnBehaviorComplete": [{}],
                     "OnReset": []},
        "conclusion": {"behavior_manager_dispatches_on_reset": False,
                       "runtime_completion_dispatches_present": True}}
    reset_closed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out10", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", tmp_path / "receiver-join.json",
        tmp_path / "ancestor-join.json", tmp_path / "enum.json",
        _write(tmp_path / "reset-audit.json", reset_audit))
    assert not any(row["claim"] == "task reset lifecycle for selected parameter tasks"
                   for row in reset_closed["runtime_open"])
    assert any(row["claim"] == "selected parameter task OnReset runtime callback"
               for row in reset_closed["classified_not_gameplay_repetition_gaps"])

    exact_plan = {"schema": "uc.capture-plan.v1", "plan_id": "controller-exact-closure-v1",
                  "plan_revision": 1, "scope": {"automatic_stop": False,
                      "purpose": "bounded final closure"},
                  "points": [{"retention": {"exact_callers": [{}, {}]}}] + [{}] * 4}
    planned = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out11", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", tmp_path / "receiver-join.json",
        tmp_path / "ancestor-join.json", tmp_path / "enum.json", tmp_path / "reset-audit.json",
        _write(tmp_path / "exact-plan.json", exact_plan))
    assert planned["runtime_required_now"] is True
    assert planned["next_capture"]["points"] == 5

    exact_runtime = {"schema": "uc.controller-exact-closure-runtime-analysis.v1",
        "checks": {"entry_session_accepted": True, "store_clean": True},
        "animator_invoker": {"selected_bridge_count": 123}}
    nested_runtime = {"schema": "uc.controller-nested-condition-runtime-analysis.v1",
        "conditions": {"status": "OBSERVED_EXPECTED_CONDITION_SET",
            "matching_signature_count": 5, "expected_static": [{"condition": x} for x in range(5)]},
            "object_relations": {"conditional_evaluator_to_task_consistent": True,
                "task_to_owner_consistent": True, "owners": [0x1234],
                "matching_condition_owners": [0x1234],
            "identity_level": "ObjectCandidate"}}
    observed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
        tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
        tmp_path / "dispatch.json", tmp_path / "out12", tmp_path / "accepted-frontier.json",
        None, tmp_path / "field.json", tmp_path / "runtime-join.json", tmp_path / "stage.json",
        tmp_path / "decode.json", tmp_path / "ghidra.json", tmp_path / "static-gap.json",
        tmp_path / "closure-acceptance.json", tmp_path / "closure-callers.json",
        tmp_path / "task-join.json", tmp_path / "receiver-join.json",
        tmp_path / "ancestor-join.json", tmp_path / "enum.json", tmp_path / "reset-audit.json",
        tmp_path / "exact-plan.json", _write(tmp_path / "exact-runtime.json", exact_runtime),
        _write(tmp_path / "nested-runtime.json", nested_runtime))
    assert observed["runtime_required_now"] is False
    assert "next_capture" not in observed
    assert any(row["claim"] == "Remielle five serialized condition signatures runtime execution"
               for row in observed["closed_bounded"])


def test_rejects_unclosed_bridge_abi(tmp_path: Path) -> None:
    role = {"summary": {"wrapper_observed": 0, "wrapper_total": 0,
        "native_implementation_observed": 0, "native_implementation_total": 0}}
    animator = {"checks": {"all_logical_edges_static_verified": True}}
    acceptance = {"accepted": True, "game_runtime_verified": True, "points": []}
    api = {"scope": {"selectedEncryptedApiTargetsClosed": True,
        "selectedBridgeInvocationAbiClosed": False}}
    callers = {"summary": {"unresolved_rows": 0}}
    occurrence = {"checks": {"scanned_occurrence_count": 1, "ok": True},
                  "occurrences": [{}]}
    dispatch = {"checks": {"ok": True}, "classifications": []}
    try:
        run(_write(tmp_path / "role.json", role), _write(tmp_path / "acceptance.json", acceptance),
            _write(tmp_path / "anim.json", animator), _write(tmp_path / "api.json", api),
            _write(tmp_path / "callers.json", callers), _write(tmp_path / "occ.json", occurrence),
            _write(tmp_path / "dispatch.json", dispatch), tmp_path / "out")
    except ValueError as error:
        assert "bridge invocation ABI" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_external_target_arena_join_is_bounded_and_accounted(tmp_path: Path) -> None:
    role = {"summary": {"wrapper_observed": 0, "wrapper_total": 0,
        "native_implementation_observed": 0, "native_implementation_total": 0}}
    animator = {"checks": {"all_logical_edges_static_verified": True,
        "logical_edge_count": 0, "catalog_anchored_edge_count": 0}}
    acceptance = {"accepted": True, "game_runtime_verified": True, "points": []}
    api = {"scope": {"selectedEncryptedApiTargetsClosed": True,
        "selectedBridgeInvocationAbiClosed": True}, "invoke": {"unitySlotRva": 1,
        "gameTargetRva": 2, "invokerRva": 3, "bridgeCodeRva": 4,
        "argumentRegisters": ["RCX"], "liveInvocationObserved": False}}
    callers = {"summary": {"unresolved_rows": 0}}
    occurrence = {"checks": {"scanned_occurrence_count": 1, "ok": True},
                  "occurrences": [{}]}
    dispatch = {"checks": {"ok": True}, "classifications": []}
    coverage = {"schema": "uc.ability-executor-coverage-ledger.v1", "summary": {
        "types": 188, "positions_complete_types": 188,
        "methods": 20, "exact_pdata_entries": 10, "fully_decoded_pdata_bodies": 10,
        "pdata_less_entries": 10, "direct_calls": 100, "indirect_calls": 353,
        "direct_calls_to_selected_catalog": 25, "unknown_boundary_entries": 0}}
    dependency = {"schema": "uc.ability-executor-dependency-frontier.v1", "summary": {
        "indirect_callsites": 353, "external_direct_calls": 100,
        "unique_external_direct_targets": 707,
        "source_identified_or_annotated_targets": 196,
        "stratum_counts": {}, "target_boundary_counts": {}}}
    body = {"schema": "uc.ability-external-target-body-ledger.v1", "summary": {
        "targets": 707, "exact_pdata_bodies": 705, "unidentified_targets": 511,
        "unidentified_callsites": 8216,
        "unidentified_callsites_in_direct_call_then_trap_stubs": 3296,
        "body_class_counts": {"NO_EXACT_PDATA_ENTRY": 2},
        "nested_direct_calls_with_catalog_identity": 441}}
    arena = {"schema": "uc.ability-external-target-arena-join.v1", "summary": {
        "requested_unidentified_exact_pdata_targets": 509,
        "targets_with_arena_method_candidate": 5,
        "targets_with_exact_class_list_identity": 1,
        "targets_not_present_in_preserved_arena": 504,
        "unique_joined_classes": 3,
        "joined_class_counts": {"EntityHandle": 1, "Type": 1, "X": 3}}}
    result = run(
        _write(tmp_path / "role.json", role),
        _write(tmp_path / "acceptance.json", acceptance),
        _write(tmp_path / "anim.json", animator), _write(tmp_path / "api.json", api),
        _write(tmp_path / "callers.json", callers), _write(tmp_path / "occ.json", occurrence),
        _write(tmp_path / "dispatch.json", dispatch), tmp_path / "out-arena",
        ability_executor_coverage_path=_write(tmp_path / "coverage.json", coverage),
        ability_dependency_frontier_path=_write(tmp_path / "dependency.json", dependency),
        ability_external_target_body_ledger_path=_write(tmp_path / "body.json", body),
        ability_external_target_arena_join_path=_write(tmp_path / "arena.json", arena))
    claim = next(row for row in result["closed_bounded"]
                 if row["claim"] ==
                 "Ability external target preserved-arena ownership candidates")
    assert claim["targets_with_arena_method_candidate"] == 5
    assert result["runtime_required_now"] is False

    dynamic_plan = {
        "schema": "uc.ability-dynamic-dispatch-plan-report.v1",
        "activation_ready": False, "runtime_required_now": True,
        "unresolved_initialized_slots": 21, "dynamic_callsites": 36,
        "physical_dynamic_probe_sites": 35, "coalesced_adjacent_callsites": 1,
        "qualification_sites": 36, "near_only_qualification_sites": 10,
        "direct_relocation_interior_edges": 0,
        "plan": {"path": "source-plan.json", "sha256": "1" * 64},
        "qualification": {"path": "qualification.json", "sha256": "2" * 64},
        "static_contract": {"path": "static-contract.json", "sha256": "3" * 64},
    }
    planned = run(
        tmp_path / "role.json", tmp_path / "acceptance.json",
        tmp_path / "anim.json", tmp_path / "api.json", tmp_path / "callers.json",
        tmp_path / "occ.json", tmp_path / "dispatch.json", tmp_path / "out-dynamic",
        ability_executor_coverage_path=tmp_path / "coverage.json",
        ability_dependency_frontier_path=tmp_path / "dependency.json",
        ability_external_target_body_ledger_path=tmp_path / "body.json",
        ability_external_target_arena_join_path=tmp_path / "arena.json",
        ability_dynamic_dispatch_plan_path=_write(tmp_path / "dynamic-plan.json", dynamic_plan))
    assert planned["runtime_required_now"] is True
    assert planned["next_capture"]["qualification_sites"] == 36
    assert planned["next_capture"]["physical_dynamic_probe_sites"] == 35

    runtime = {
        "schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
        "sources": {"static_contract": {"sha256": "3" * 64}},
        "summary": {
            "initialized_slots_expected": 21,
            "initialized_slots_observed": 21,
            "initialized_slots_stable": 21,
            "logical_dynamic_callsites": 36,
            "physical_dynamic_probe_sites": 35,
            "observed_dynamic_probe_sites": 20,
            "unobserved_dynamic_probe_sites": 15,
            "semantic_callee_names_assigned": 0,
        },
        "session": {"cleanup": "STOPPED_CLEAN", "storage_complete": True,
                    "loss_events": 0, "coverage_complete_points": 36,
                    "event_count": 28992},
    }
    runtime_path = _write(tmp_path / "dynamic-runtime.json", runtime)
    runtime_hash = file_hash(runtime_path)
    method_join = {
        "schema": "uc.ability-dynamic-dispatch-method-join.v1",
        "sources": {"runtime_analysis": {"sha256": runtime_hash}},
        "summary": {"observed_game_target_rvas": 18,
                    "exact_catalogued_method_targets": 9,
                    "uncatalogued_method_targets": 9,
                    "observed_class_target_pairs": 17},
    }
    slot_join = {
        "schema": "uc.ability-initialized-slot-import-join.v1",
        "sources": {"runtime_analysis": {"sha256": runtime_hash}},
        "summary": {"initialized_slots": 21, "pe_import_slots": 3,
                    "non_import_initialized_slots": 18},
    }
    consumed = run(
        tmp_path / "role.json", tmp_path / "acceptance.json",
        tmp_path / "anim.json", tmp_path / "api.json", tmp_path / "callers.json",
        tmp_path / "occ.json", tmp_path / "dispatch.json", tmp_path / "out-dynamic-runtime",
        ability_executor_coverage_path=tmp_path / "coverage.json",
        ability_dependency_frontier_path=tmp_path / "dependency.json",
        ability_external_target_body_ledger_path=tmp_path / "body.json",
        ability_external_target_arena_join_path=tmp_path / "arena.json",
        ability_dynamic_dispatch_plan_path=tmp_path / "dynamic-plan.json",
        ability_dynamic_dispatch_runtime_path=runtime_path,
        ability_dynamic_dispatch_method_join_path=_write(
            tmp_path / "dynamic-method-join.json", method_join),
        ability_initialized_slot_import_join_path=_write(
            tmp_path / "slot-import-join.json", slot_join))
    assert consumed["runtime_required_now"] is False
    assert "next_capture" not in consumed
    assert consumed["next_work"][0].startswith("map the 9 uncatalogued")
    dynamic_claim = next(row for row in consumed["closed_bounded"]
                         if row["claim"] ==
                         "Ability dynamic dispatch targets observed in complete covered session")
    assert dynamic_claim["observed_dynamic_probe_sites"] == 20
    assert dynamic_claim["unobserved_dynamic_probe_sites"] == 15

    method_join_path = tmp_path / "dynamic-method-join.json"
    slot_join_path = tmp_path / "slot-import-join.json"
    authoritative = {
        "schema": "uc.ability-dynamic-dispatch-authoritative-method-join.v1",
        "sources": {"base_method_join": {"sha256": file_hash(method_join_path)}},
        "summary": {"base_exact_catalogued_method_targets": 9,
                    "exact_catalogued_method_targets": 13,
                    "newly_catalogued_method_targets": 4,
                    "observed_class_target_pairs": 17,
                    "observed_game_target_rvas": 18,
                    "uncatalogued_method_targets": 5},
    }
    authoritative_path = _write(tmp_path / "authoritative.json", authoritative)
    consumers = {
        "schema": "uc.ability-initialized-slot-consumer-join.v1",
        "sources": {"initialized_slot_import_join": {"sha256": file_hash(slot_join_path)}},
        "summary": {"initialized_slots": 21, "non_import_slots": 18,
                    "non_import_slots_with_static_consumers": 18,
                    "non_import_slots_with_unresolved_initializer": 18,
                    "pe_import_slots": 3, "slots_with_static_consumers": 21,
                    "static_consumer_callsites": 58},
    }
    scan = {"schema": "uc.ability-private-load-multipass-scan.v1",
            "summary": {"target_rvas": 5, "requested_types": 9121,
                        "covered_types": 9121, "uncovered_types": 0,
                        "exact_positive_matches": 0, "scan_complete": True}}
    scan_path = _write(tmp_path / "multipass-scan.json", scan)
    dynamic_body = {
        "schema": "uc.ability-dynamic-target-body-ledger.v1",
        "sources": {
            "authoritative_method_join": {"sha256": file_hash(authoritative_path)},
            "multipass_owner_scan": {"sha256": file_hash(scan_path)}},
        "summary": {"uncatalogued_dynamic_targets": 5, "exact_pdata_bodies": 5,
                    "fully_decoded_bodies": 5,
                    "complete_private_load_owner_scan_types": 9121,
                    "private_load_exact_owner_matches": 0,
                    "exact_fast_path_field_loads": 2},
    }
    relevance = {
        "schema": "uc.ability-unobserved-static-relevance.v1",
        "sources": {"runtime_analysis": {"sha256": runtime_hash}},
        "summary": {"unobserved_physical_probe_sites": 15,
                    "represented_unobserved_callsites": 15,
                    "callsites_with_remielle_origin_asset_occurrences": 15,
                    "unique_caller_types": 8,
                    "classification_counts": {
                        "RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH": 14,
                        "STATIC_INITIALIZER_TIMING_SITE": 1}},
    }
    offline = run(
        tmp_path / "role.json", tmp_path / "acceptance.json",
        tmp_path / "anim.json", tmp_path / "api.json", tmp_path / "callers.json",
        tmp_path / "occ.json", tmp_path / "dispatch.json", tmp_path / "out-dynamic-offline",
        ability_executor_coverage_path=tmp_path / "coverage.json",
        ability_dependency_frontier_path=tmp_path / "dependency.json",
        ability_external_target_body_ledger_path=tmp_path / "body.json",
        ability_external_target_arena_join_path=tmp_path / "arena.json",
        ability_dynamic_dispatch_plan_path=tmp_path / "dynamic-plan.json",
        ability_dynamic_dispatch_runtime_path=runtime_path,
        ability_dynamic_dispatch_method_join_path=method_join_path,
        ability_initialized_slot_import_join_path=slot_join_path,
        ability_dynamic_dispatch_authoritative_join_path=authoritative_path,
        ability_initialized_slot_consumer_join_path=_write(
            tmp_path / "slot-consumers.json", consumers),
        ability_dynamic_target_multipass_scan_path=scan_path,
        ability_dynamic_target_body_ledger_path=_write(
            tmp_path / "dynamic-body.json", dynamic_body),
        ability_unobserved_static_relevance_path=_write(
            tmp_path / "unobserved-relevance.json", relevance))
    assert offline["runtime_required_now"] is False
    assert offline["next_work"][0].startswith("decode predecessor branches")
    method_claim = next(row for row in offline["closed_bounded"]
                        if row["claim"] ==
                        "runtime dynamic targets joined to authoritative method harvests")
    assert method_claim["exact_catalogued_method_targets"] == 13

    relevance_path = tmp_path / "unobserved-relevance.json"
    branch = {
        "schema": "uc.ability-unobserved-branch-ledger.v1",
        "sources": {"static_relevance": {"sha256": file_hash(relevance_path)}},
        "summary": {
            "runtime_conditional_sites": 14, "semantic_predicates_assigned": 0,
            "sites_mandatory_in_complete_mechanical_cfg": 0,
            "sites_not_reached_by_current_mechanical_cfg": 0,
            "sites_reachable_but_not_mandatory_in_complete_mechanical_cfg": 14,
            "sites_reachable_in_current_mechanical_cfg": 14,
            "sites_with_exact_caller_body": 14,
            "sites_with_mechanical_gating_branch": 10,
            "sites_with_outcome_sensitive_branch": 14,
            "sites_with_remaining_unresolved_indirect_control": 0,
            "total_mechanical_gating_branches": 48,
            "total_outcome_sensitive_branches": 183,
        },
    }
    branch_path = _write(tmp_path / "branch.json", branch)
    predicate = {
        "schema": "uc.ability-unobserved-predicate-join.v1",
        "sources": {"branch_ledger": {"sha256": file_hash(branch_path)}},
        "summary": {
            "exact_field_identities_assigned": 0,
            "predicate_shape_counts": {"MEMORY_COMPARE": 1,
                                       "REGISTER_ZERO_TEST": 9,
                                       "RIP_RELATIVE_MEMORY_COMPARE_ZERO": 4},
            "selection_counts": {
                "NEAREST_PRECEDING_NON_DOMINATING_OUTCOME_SENSITIVE_BRANCH": 4,
                "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE": 10},
            "semantic_gameplay_predicates_assigned": 0, "sites": 14,
            "sites_with_harvested_field_offset_candidates": 7,
        },
    }
    consumer_path = tmp_path / "slot-consumers.json"
    module = {
        "schema": "uc.ability-initialized-slot-module-join.v1",
        "sources": {"consumer_join": {"sha256": file_hash(consumer_path)}},
        "summary": {
            "candidate_modules_scanned": 17, "initializer_write_sites_resolved": 0,
            "non_import_slots": 18, "selected_module": "UnityPlayer.dll",
            "selected_runtime_base": 140717056131072,
            "slots_with_exact_module_pdata_target": 18,
            "unique_exact_module_pdata_targets": 17,
            "unique_full_exact_module_base_matches": 1, "unique_runtime_targets": 17,
        },
    }
    module_path = _write(tmp_path / "slot-module.json", module)
    xrefs = {
        "schema": "uc.ability-initialized-slot-pdata-xrefs.v1",
        "sources": {"consumer_join": {"sha256": file_hash(consumer_path)}},
        "summary": {
            "access_counts": {"READ": 3894}, "exact_rip_relative_references": 3894,
            "fully_linearly_decoded_pdata_records": 1355043,
            "incompletely_linearly_decoded_pdata_records": 322,
            "non_import_slots": 18, "pdata_records": 1355365,
            "referenced_slots": 18, "slots_with_pdata_write_reference": 0,
            "slots_without_pdata_write_reference": 18,
        },
    }
    xrefs_path = _write(tmp_path / "slot-xrefs.json", xrefs)
    storage = {
        "schema": "uc.ability-initialized-slot-storage-ledger.v1",
        "sources": {"module_join": {"sha256": file_hash(module_path)},
                    "pdata_xrefs": {"sha256": file_hash(xrefs_path)}},
        "summary": {
            "initializer_write_sites_resolved": 0, "slots": 18,
            "slots_in_data_section": 18,
            "slots_with_exact_runtime_target_module_rva": 18,
            "slots_without_decoded_gameassembly_pdata_write_reference": 18,
            "slots_without_file_backed_initial_value": 18,
            "storage_counts": {"VIRTUAL_ZERO_FILL_TAIL": 18},
        },
    }
    predicate_path = _write(tmp_path / "predicate.json", predicate)
    base_identity = {
        "schema": "uc.ability-unobserved-base-identity-join.v1",
        "sources": {"predicate_join": {"sha256": file_hash(predicate_path)}},
        "summary": {
            "sites": 14, "sites_with_stable_nonvolatile_this_alias": 12,
            "sites_with_exact_field_access_in_selected_window": 5,
            "selected_test_values_with_exact_object_provenance": 2,
            "semantic_gameplay_predicates_assigned": 0,
        },
    }
    branched = run(
        tmp_path / "role.json", tmp_path / "acceptance.json",
        tmp_path / "anim.json", tmp_path / "api.json", tmp_path / "callers.json",
        tmp_path / "occ.json", tmp_path / "dispatch.json", tmp_path / "out-dynamic-branch",
        ability_executor_coverage_path=tmp_path / "coverage.json",
        ability_dependency_frontier_path=tmp_path / "dependency.json",
        ability_external_target_body_ledger_path=tmp_path / "body.json",
        ability_external_target_arena_join_path=tmp_path / "arena.json",
        ability_dynamic_dispatch_plan_path=tmp_path / "dynamic-plan.json",
        ability_dynamic_dispatch_runtime_path=runtime_path,
        ability_dynamic_dispatch_method_join_path=method_join_path,
        ability_initialized_slot_import_join_path=slot_join_path,
        ability_dynamic_dispatch_authoritative_join_path=authoritative_path,
        ability_initialized_slot_consumer_join_path=consumer_path,
        ability_dynamic_target_multipass_scan_path=scan_path,
        ability_dynamic_target_body_ledger_path=tmp_path / "dynamic-body.json",
        ability_unobserved_static_relevance_path=relevance_path,
        ability_unobserved_branch_ledger_path=branch_path,
        ability_unobserved_predicate_join_path=predicate_path,
        ability_initialized_slot_module_join_path=module_path,
        ability_initialized_slot_pdata_xrefs_path=xrefs_path,
        ability_initialized_slot_storage_ledger_path=_write(
            tmp_path / "slot-storage.json", storage),
        ability_unobserved_base_identity_join_path=_write(
            tmp_path / "base-identity.json", base_identity))
    assert branched["runtime_required_now"] is False
    assert branched["next_work"][0].startswith("compile one merged read-only branch-input plan")
    slot_claim = next(row for row in branched["closed_bounded"]
                      if row["claim"] ==
                      "initialized Ability slot runtime target module and RVA identity")
    assert slot_claim["module"] == "UnityPlayer.dll"
    ability_gap = next(row for row in branched["offline_open"]
                       if row["claim"] ==
                       "Ability executor semantic and external dependency audit")
    assert ability_gap["unobserved_sites_with_strong_dominating_gate"] == 10
    assert ability_gap["unobserved_selected_test_values_with_exact_object_provenance"] == 2
