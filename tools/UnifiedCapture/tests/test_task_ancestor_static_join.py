from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from task_ancestor_static_join import analyze


def test_joins_exact_serialized_ancestor_chain():
    task_join = {"schema": "uc.task-context-static-join.v1", "behavior_trees": [{
        "identity_status": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
        "candidate_static_trees": [{
            "root_tree": "Behavior_Avatar_RemielleOrigin_Decision",
            "matched_tasks": [{"runtime_task_index": 17, "native_type_index": 3,
                "static_rows": [{"serialized_subtree": "Skill", "serialized_task_index": 3,
                                 "type": "SetValue", "parameter_name": "Value"}]}]}]}]}
    trees = {"trees": [{"name": "Skill", "tasks": [
        {"index": 0, "type": "Entry", "parentIndex": -1, "childIndices": [1]},
        {"index": 1, "type": "ConditionalEvaluator", "parentIndex": 0, "childIndices": [2],
         "fields": [
             {"fieldNameHash": 10, "mechanicalUtf8": "Int_Mode"},
             {"fieldNameHash": 11, "mechanicalInt32LE": 5},
         ]},
        {"index": 2, "type": "Sequence", "parentIndex": 1, "childIndices": [3]},
        {"index": 3, "type": "SetValue", "parentIndex": 2, "childIndices": []},
    ]}]}
    field_map = {"resolved": {
        "100": {"fieldName": "integer1", "fieldType": "SharedInt"},
        "101": {"fieldName": "integer2", "fieldType": "SharedInt"},
        "10": {"fieldName": "Name", "fieldType": "String", "candidates": [
            {"hashPrefix": 100}]},
        "11": {"fieldName": "mValue", "fieldType": "Int32", "candidates": [
            {"hashPrefix": 101}]},
    }}
    result = analyze(task_join, trees, field_map)
    assert result["summary"]["joined_task_signatures"] == 1
    assert result["summary"]["unique_ancestor_chains"] == 1
    assert result["task_ancestor_rows"][0]["ancestor_chain"] == [
        {"index": 0, "type": "Entry", "child_indices": [1]},
        {"index": 1, "type": "ConditionalEvaluator", "child_indices": [2]},
        {"index": 2, "type": "Sequence", "child_indices": [3]},
    ]
    assert result["task_ancestor_rows"][0]["ancestor_conditions"] == [{
        "tree": "Skill", "task_index": 1,
        "integer1_shared_name": "Int_Mode", "integer2_constant_raw": 5}]


def test_rejects_type_mismatch():
    task_join = {"schema": "uc.task-context-static-join.v1", "behavior_trees": [{
        "identity_status": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
        "candidate_static_trees": [{
            "root_tree": "Behavior_Avatar_RemielleOrigin_Decision",
            "matched_tasks": [{"runtime_task_index": 1, "native_type_index": 2,
                "static_rows": [{"serialized_subtree": "Tree", "serialized_task_index": 0,
                                 "type": "Expected"}]}]}]}]}
    trees = {"trees": [{"name": "Tree", "tasks": [
        {"index": 0, "type": "Actual", "parentIndex": -1, "childIndices": []}]}]}
    try:
        analyze(task_join, trees, {"resolved": {}})
    except ValueError as error:
        assert "disagrees" in str(error)
    else:
        raise AssertionError("expected ValueError")
