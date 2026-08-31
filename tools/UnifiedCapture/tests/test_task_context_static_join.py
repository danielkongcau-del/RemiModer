from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from task_context_static_join import analyze_events


def _event(event_id, point, registers, task, qpc=15):
    return {"event_id": event_id, "generation": 2, "point": point, "qpc": qpc,
            "raw_abi": {"registers": registers},
            "reads": [{"id": "raw-rcx", "status": 1, "value": task}]}


def test_runtime_register_context_uniquely_matches_static_tree():
    start = "SetBoolParameter.OnStart@0x1/entry"
    update = "SetBoolParameter.OnUpdate@0x2/entry"
    join = {"runtime_callsite_rows": [
        {"callee_point": start, "caller_method_identities": [
            {"owner": "BehaviorManager", "method": "PushTask"}]},
        {"callee_point": update, "caller_method_identities": [
            {"owner": "BehaviorManager", "method": "RunTask"}]},
    ]}
    events = [
        _event(1, start, {"rdi": 0x1000, "rsi": 7}, 0x2000),
        _event(2, update, {"rsi": 0x1000, "rbx": 7}, 0x2000, 16),
    ]
    intervals = [{"label": "A->B", "begin_qpc_exclusive": 10,
                  "end_qpc_exclusive": 20, "complete": True}]
    links = [
        {"abTree": "TreeAChild", "route": [{"fromTree": "TreeA", "toTree": "TreeAChild"}],
         "runtimeIndex": 7, "nativeTypeIndex": 3,
         "parameterName": "Flag", "type": "SetBool",
         "currentParameterRecord": [1, 2, 3, 4],
         "staticParameterTargets": [{"controller": "ControllerA", "record": [1, 2, 3, 4]}]},
        {"abTree": "TreeB", "runtimeIndex": 8, "nativeTypeIndex": 3,
         "parameterName": "Other", "type": "SetBool"},
    ]
    result = analyze_events(events, intervals, {start: 3, update: 3}, join, links, 2)
    assert result["summary"] == {
        "task_contexts": 1, "behavior_tree_addresses": 1,
        "unique_static_tree_matches": 1, "ambiguous_static_tree_matches": 0,
        "unmatched_tree_addresses": 0, "rejected_events": 0}
    match = result["behavior_trees"][0]["candidate_static_trees"][0]
    assert match["root_tree"] == "TreeA"
    assert match["matched_tasks"][0]["static_rows"][0]["serialized_subtree"] == "TreeAChild"
    assert match["matched_tasks"][0]["static_rows"][0]["current_parameter_record"] == [1, 2, 3, 4]
    assert match["matched_tasks"][0]["static_rows"][0]["static_parameter_targets"][0][
        "controller"] == "ControllerA"
    assert result["contexts"][0]["task_addresses"] == [0x2000]


def test_missing_source_identified_caller_is_rejected():
    point = "SetBoolParameter.OnUpdate@0x2/entry"
    event = _event(1, point, {"rsi": 0x1000, "rbx": 7}, 0x2000)
    result = analyze_events([event], [], {point: 3}, {"runtime_callsite_rows": []}, [], 2)
    assert result["summary"]["task_contexts"] == 0
    assert result["summary"]["rejected_events"] == 1
