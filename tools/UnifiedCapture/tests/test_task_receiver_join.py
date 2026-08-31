from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from task_receiver_join import analyze


def _authority():
    return {"schema": "zzz.existing-task-register-consumption.v1",
            "nativeMethods": [
                {"typeIndex": 34455, "method": "OnUpdate", "rva": 100},
                {"typeIndex": 34459, "method": "OnUpdate", "rva": 200},
                {"typeIndex": 41564, "method": "OnUpdate", "rva": 300},
            ], "nativeWitness": {"checkedInstructions": [
                {"rva": 110, "mnemonic": "mov", "operands": "qword ptr [rsi + 0x70]"},
                {"rva": 210, "mnemonic": "mov", "operands": "qword ptr [rsi + 0x70]"},
                {"rva": 310, "mnemonic": "mov", "operands": "qword ptr [rsi + 0x58]"},
            ]}}


def test_joins_direct_and_component_receivers():
    tree = {"behavior_tree_address": 0x1000,
            "identity_status": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
            "candidate_static_trees": [{"root_tree": "Behavior_Avatar_RemielleOrigin_Decision"}],
            "observed_task_signature": [
                {"runtime_task_index": 7, "native_type_index": 34459},
                {"runtime_task_index": 8, "native_type_index": 41564}]}
    task_join = {"schema": "uc.task-context-static-join.v1", "behavior_trees": [tree],
                 "contexts": [
                     {"behavior_tree_address": 0x1000, "runtime_task_index": 7,
                      "native_type_index": 34459, "task_addresses": [0x2000]},
                     {"behavior_tree_address": 0x1000, "runtime_task_index": 8,
                      "native_type_index": 41564, "task_addresses": [0x3000]},
                 ]}
    lifecycle = {"schema": "uc.controller-field-lifecycle-analysis.v1", "candidates": [
        {"candidate_kind": "parameter-task", "observed_address": 0x2000,
         "field_values": {"animator-object": [0, 0x4000]}},
        {"candidate_kind": "parameter-task", "observed_address": 0x3000,
         "field_values": {"animator-component": [0x5000], "owner-entity": [0x6000]}},
    ]}
    result = analyze(task_join, lifecycle, _authority())
    assert result["summary"] == {
        "matched_task_contexts": 2,
        "direct_animator_tasks": 1,
        "component_animator_tasks": 1,
        "unique_direct_animator_addresses": 1,
        "unique_animator_component_addresses": 1,
        "unique_trigger_owner_entities": 1,
        "direct_animator_address": 0x4000,
        "animator_component_address": 0x5000,
        "trigger_owner_entity": 0x6000,
    }


def test_rejects_ambiguous_receiver():
    tree = {"behavior_tree_address": 1,
            "identity_status": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
            "candidate_static_trees": [{"root_tree": "Behavior_Avatar_RemielleOrigin_Decision"}],
            "observed_task_signature": [{"runtime_task_index": 1, "native_type_index": 34455}]}
    task_join = {"schema": "uc.task-context-static-join.v1", "behavior_trees": [tree],
                 "contexts": [{"behavior_tree_address": 1, "runtime_task_index": 1,
                               "native_type_index": 34455, "task_addresses": [2]}]}
    lifecycle = {"schema": "uc.controller-field-lifecycle-analysis.v1", "candidates": [
        {"candidate_kind": "parameter-task", "observed_address": 2,
         "field_values": {"animator-object": [3, 4]}}]}
    try:
        analyze(task_join, lifecycle, _authority())
    except ValueError as error:
        assert "ambiguous" in str(error)
    else:
        raise AssertionError("expected ValueError")
