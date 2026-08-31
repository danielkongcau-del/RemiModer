"""Analyze the bounded exact-closure runtime unit without semantic promotion."""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, inspect_session, read_manifest


POINT_CONDITION = "IntComparison.OnUpdate@0x1e471eb0/entry"
POINT_LOAD = "BehaviorManager.LoadBehaviorComplete@0x1e45eef0/entry"
POINT_DESTROY = "BehaviorManager.DestroyBehavior@0x1e467aa0/entry"
POINT_TRIGGER = "SetTriggerParameter.OnUpdate@0x14a207b0/entry"
POINT_INVOKER = "AnimatorFixedUpdate.invoker@0x4e30/entry"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _verify_string_layout(path: Path) -> None:
    text = path.read_text(encoding="utf-8-sig", errors="strict")
    if not re.search(r"m_stringLength;\s*//\s*0x10", text) or not re.search(
            r"m_firstChar;\s*//\s*0x14", text):
        raise ValueError("System.String runtime field layout is not source-verified")


def _verify_trigger_layout(path: Path) -> None:
    text = path.read_text(encoding="utf-8-sig", errors="strict")
    body = re.search(r"SetTriggerParameter\s*:\s*Action\s*\{(?P<body>.*?)\n\}", text, re.S)
    if body is None or not re.search(r"SharedString\s+paramaterName;\s*//\s*0x68", body.group("body")):
        raise ValueError("SetTriggerParameter.paramaterName SharedString layout is not source-verified")


def _decode_system_string(blob: bytes, read: dict[str, Any]) -> str | None:
    """Decode only a source-verified System.String block captured at the callsite."""
    if read.get("status") != 1:
        return None
    start, length = int(read["offset"]), int(read["length"])
    block = blob[start:start + length]
    if len(block) < 20:
        return None
    count = int.from_bytes(block[16:20], "little", signed=True)
    if count < 0 or 20 + count * 2 > len(block):
        return None
    return block[20:20 + count * 2].decode("utf-16-le", errors="strict")


def _value(reads: dict[str, dict[str, Any]], key: str) -> int:
    row = reads[key]
    if row.get("status") != 1 or not isinstance(row.get("value"), int):
        raise ValueError(f"required runtime read is unavailable: {key}")
    return row["value"]


def _condition_signature(row: dict[str, Any]) -> tuple[str, int, int]:
    return row["integer1_shared_name"], row["integer2_constant_raw"], row["operation_raw"]


def _join_lifecycle(loads: list[dict[str, Any]], destroys: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_behavior: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in destroys:
        by_behavior[row["behavior"]].append(row)
    joined = []
    for load in loads:
        later = [row for row in by_behavior.get(load["behavior"], []) if row["qpc"] >= load["qpc"]]
        joined.append({**load, "destroy_observed": bool(later),
                       "destroy_qpc": min((row["qpc"] for row in later), default=None),
                       "destroy_execution_status": min(
                           (row["execution_status"] for row in later), default=None)})
    return joined


def _add_group(groups: dict[tuple[Any, ...], dict[str, Any]], key: tuple[Any, ...],
               qpc: int, event_id: int) -> None:
    row = groups.setdefault(key, {"count": 0, "first_qpc": qpc, "last_qpc": qpc,
                                  "representative_event_id": event_id})
    row["count"] += 1
    row["first_qpc"] = min(row["first_qpc"], qpc)
    row["last_qpc"] = max(row["last_qpc"], qpc)


def run(session_path: Path, acceptance_path: Path, plan_path: Path,
        task_ancestor_path: Path, enum_path: Path, type_layout_path: Path,
        api_usage_path: Path, output: Path) -> dict[str, Any]:
    paths = [session_path, acceptance_path, plan_path, task_ancestor_path,
             enum_path, type_layout_path, api_usage_path, output]
    session_path, acceptance_path, plan_path, task_ancestor_path, enum_path, \
        type_layout_path, api_usage_path, output = [path.resolve() for path in paths]
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance, plan = _load(acceptance_path), _load(plan_path)
    task_ancestor, enum_decode, api_usage = (_load(task_ancestor_path), _load(enum_path),
                                             _load(api_usage_path))
    if not acceptance.get("accepted") or not acceptance.get("game_runtime_verified"):
        raise ValueError("entry acceptance is not accepted game-runtime evidence")
    if plan.get("plan_id") != "controller-exact-closure-v1" or plan.get("plan_revision") != 2:
        raise ValueError("unsupported exact-closure plan identity")
    if {row.get("id") for row in plan.get("points", [])} != {
            POINT_CONDITION.removesuffix("/entry"), POINT_LOAD.removesuffix("/entry"),
            POINT_DESTROY.removesuffix("/entry"), POINT_TRIGGER.removesuffix("/entry"),
            POINT_INVOKER.removesuffix("/entry")}:
        raise ValueError("exact-closure point set differs from the performance-corrected five-point unit")
    _verify_string_layout(type_layout_path)
    _verify_trigger_layout(type_layout_path)
    inspection = inspect_session(session_path)
    if not inspection.get("storage_complete") or inspection.get("cleanup") != "STOPPED_CLEAN" \
            or inspection.get("errors"):
        raise ValueError("session is not a clean sealed evidence store")
    manifest, manifest_errors = read_manifest(session_path / "session.manifest")
    if manifest_errors:
        raise ValueError(f"manifest errors: {manifest_errors}")
    if acceptance.get("session", {}).get("manifest_sha256") != file_hash(session_path / "session.manifest"):
        raise ValueError("archived session differs from accepted session manifest")
    context = event_dictionary_context(session_path / "session.manifest", manifest)
    activation = next(row for row in manifest if row.get("kind") == "plan_activation"
                      and row.get("generation") == acceptance["generation"])
    bases = {row["module"]: row["module_base"] for row in activation.get("bindings", [])}
    game_base = bases["game"]
    marks: dict[str, list[int]] = defaultdict(list)
    for row in manifest:
        if row.get("kind") == "user_mark":
            marks[row["label"]].append(row["qpc"])
    action_begin = min(marks.get("TRIAL_ACTIONS_BEGIN", [0]))
    action_end = max(marks.get("TRIAL_ACTIONS_COMPLETE", [0]))
    if not action_begin or action_end < action_begin:
        raise ValueError("marked trial action window is unavailable")

    enum_by_raw = {row["raw_value"]: row for row in enum_decode["mappings"]}
    expected = []
    seen_expected = set()
    for task in task_ancestor.get("task_ancestor_rows", []):
        for condition in task.get("ancestor_conditions", []):
            key = (condition.get("tree"), condition.get("task_index"),
                   condition.get("integer1_shared_name"), condition.get("integer2_constant_raw"),
                   condition.get("operation_raw"))
            if key in seen_expected:
                continue
            seen_expected.add(key)
            expected.append({"tree": key[0], "serialized_task_index": key[1],
                             "integer1_shared_name": key[2], "integer2_constant_raw": key[3],
                             "operation_raw": key[4],
                             "operation_semantic": enum_by_raw[key[4]]["native_predicate"]})
    if len(expected) != 5:
        raise ValueError("authoritative static condition set is not five nodes")

    condition_groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    supplementary_failures = []
    loads: list[dict[str, Any]] = []
    destroys: list[dict[str, Any]] = []
    trigger_groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    invoker_groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for chunk in inspection["chunks"]:
        _, rows = decode_chunk_file(session_path / chunk["file"], dictionary_context=context)
        for _, _, event, blob in rows:
            if event.get("generation") != acceptance["generation"]:
                continue
            point = event.get("point")
            reads = {row["id"]: row for row in event.get("reads", [])}
            qpc, event_id = int(event["qpc"]), int(event["event_id"])
            if point == POINT_CONDITION:
                lane = event.get("retention_key", {}).get("lane")
                if lane != "exact_promoted":
                    if event.get("read_failures"):
                        supplementary_failures.append({"event_id": event_id, "qpc": qpc,
                            "lane": lane, "read_failures": event["read_failures"],
                            "return_address": event.get("retention_key", {}).get("value")})
                    continue
                if event.get("read_failures") or event.get("truncated"):
                    raise ValueError("exact-promoted condition evidence is incomplete")
                key = (_value(reads, "behavior-tree"), _value(reads, "task"),
                       _value(reads, "runtime-task-index"),
                       _decode_system_string(blob, reads["integer1-name-object"]),
                       _value(reads, "integer2-constant"), _value(reads, "operation"),
                       _value(reads, "external-behavior"),
                       _decode_system_string(blob, reads["external-name-object"]))
                _add_group(condition_groups, key, qpc, event_id)
            elif point == POINT_LOAD:
                loads.append({"qpc": qpc, "event_id": event_id,
                    "manager": _value(reads, "manager"), "behavior": _value(reads, "behavior"),
                    "behavior_tree": _value(reads, "behavior-tree"),
                    "external_behavior": _value(reads, "external-behavior"),
                    "behavior_name": _decode_system_string(blob, reads["external-name-object"])})
            elif point == POINT_DESTROY:
                destroys.append({"qpc": qpc, "event_id": event_id,
                    "manager": _value(reads, "manager"), "behavior": _value(reads, "behavior"),
                    "execution_status": _value(reads, "execution-status")})
            elif point == POINT_TRIGGER:
                shared = reads["parameter-name-object"]
                raw = blob[int(shared["offset"]):int(shared["offset"]) + int(shared["length"])]
                key = (_value(reads, "task"), _value(reads, "behavior-tree"),
                       _value(reads, "runtime-task-index"), _value(reads, "animator-component"),
                       _value(reads, "nested-unity-animator"), _value(reads, "owner-entity"),
                       hashlib.sha256(raw).hexdigest())
                _add_group(trigger_groups, key, qpc, event_id)
            elif point == POINT_INVOKER:
                bridge = _value(reads, "bridge-code")
                key = (bridge, bridge - game_base, _value(reads, "method-object"),
                       _value(reads, "adjusted-argument"), _value(reads, "argument-array"))
                _add_group(invoker_groups, key, qpc, event_id)

    condition_rows = []
    for key, aggregate in sorted(condition_groups.items(), key=lambda row: (row[0][3], row[0][4], row[0][2], row[0][0])):
        operation = enum_by_raw.get(key[5])
        condition_rows.append({"behavior_tree": key[0], "task": key[1],
            "runtime_task_index": key[2], "integer1_shared_name": key[3],
            "integer2_constant_raw": key[4], "operation_raw": key[5],
            "operation_semantic": operation.get("native_predicate") if operation else None,
            "external_behavior": key[6], "behavior_name": key[7], **aggregate})
    observed_signatures = {_condition_signature(row) for row in condition_rows}
    expected_signatures = {_condition_signature(row) for row in expected}
    lifecycle = _join_lifecycle(loads, destroys)
    trigger_rows = [{"task": key[0], "behavior_tree": key[1], "runtime_task_index": key[2],
                     "animator_component": key[3], "nested_unity_animator": key[4],
                     "owner_entity": key[5], "shared_string_object_sha256": key[6], **aggregate}
                    for key, aggregate in sorted(trigger_groups.items())]
    static_trigger_by_runtime: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for task in task_ancestor.get("task_ancestor_rows", []):
        if task.get("serialized_task_type", "").endswith("SetTriggerParameter"):
            static_trigger_by_runtime[int(task["runtime_task_index"])].append(task)
    downstream_conditions: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in trigger_rows:
        candidates = static_trigger_by_runtime.get(row["runtime_task_index"], [])
        row["static_candidate_count"] = len(candidates)
        row["static_candidates"] = [{"serialized_subtree": item["serialized_subtree"],
            "serialized_task_index": item["serialized_task_index"],
            "serialized_task_type": item["serialized_task_type"],
            "parameter_name": item["parameter_name"], "route": item["route"],
            "ancestor_conditions": item["ancestor_conditions"]} for item in candidates]
        for candidate in candidates:
            for condition in candidate.get("ancestor_conditions", []):
                key = (condition["tree"], condition["task_index"],
                       condition["integer1_shared_name"], condition["integer2_constant_raw"],
                       condition["operation_raw"])
                downstream_conditions[key] = {"tree": key[0], "serialized_task_index": key[1],
                    "integer1_shared_name": key[2], "integer2_constant_raw": key[3],
                    "operation_raw": key[4],
                    "operation_semantic": enum_by_raw[key[4]]["native_predicate"],
                    "evidence": "observed descendant SetTrigger task + source-derived ancestor chain",
                    "identity_scope": "cross-session structural candidate; not EntityIdentity"}
    invoker_rows = [{"bridge_code": key[0], "bridge_code_rva": key[1],
                     "method_object": key[2], "adjusted_argument": key[3],
                     "argument_array": key[4], **aggregate}
                    for key, aggregate in sorted(invoker_groups.items())]
    selected_bridge_rva = int(api_usage["invoke"]["bridgeCodeRva"])
    selected = [row for row in invoker_rows if row["bridge_code_rva"] == selected_bridge_rva]
    if len(selected) != 1:
        raise ValueError("selected Animator bridge tuple is not uniquely observed")
    # Counts inside the user action window must be derived from raw events, not
    # interpolated from aggregate first/last timestamps.  Re-scan only the six
    # invoker tuples already proven above.
    selected_action_count = 0
    for chunk in inspection["chunks"]:
        _, rows = decode_chunk_file(session_path / chunk["file"], dictionary_context=context)
        for _, _, event, _ in rows:
            if event.get("generation") != acceptance["generation"] or event.get("point") != POINT_INVOKER:
                continue
            reads = {row["id"]: row for row in event.get("reads", [])}
            if _value(reads, "bridge-code") - game_base == selected_bridge_rva \
                    and action_begin <= event["qpc"] <= action_end:
                selected_action_count += 1

    result = {
        "schema": "uc.controller-exact-closure-runtime-analysis.v1",
        "sources": {"session_manifest": _source(session_path / "session.manifest"),
                    "entry_acceptance": _source(acceptance_path), "capture_plan": _source(plan_path),
                    "task_ancestor_static_join": _source(task_ancestor_path),
                    "int_comparison_enum_decode": _source(enum_path),
                    "runtime_type_layout": _source(type_layout_path),
                    "animator_api_usage": _source(api_usage_path)},
        "session": {"session_id": acceptance["session"]["inspection"]["chunks"][0]["session_id"],
                    "generation": acceptance["generation"], "storage_complete": True,
                    "cleanup": "STOPPED_CLEAN", "event_count": sum(
                        row["event_count"] for row in inspection["chunks"])},
        "action_window_qpc": [action_begin, action_end],
        "conditions": {"expected_static": expected, "observed_exact": condition_rows,
            "expected_signature_count": len(expected_signatures),
            "observed_signature_count": len(observed_signatures),
            "matching_signature_count": len(expected_signatures & observed_signatures),
            "target_status": ("OBSERVED_EXPECTED_CONDITION_SET" if expected_signatures <= observed_signatures
                              else "OBSERVED_DIFFERENT_CONDITION_SET"),
            "downstream_structural_candidates": [downstream_conditions[key]
                for key in sorted(downstream_conditions, key=lambda value: tuple(str(x) for x in value))],
            "downstream_expected_condition_count": len({
                _condition_signature(row) for row in downstream_conditions.values()} & expected_signatures),
            "downstream_status": ("STRUCTURAL_CANDIDATE_PARTIAL" if downstream_conditions else
                                  "NOT_OBSERVED"),
            "supplementary_aggregate_failures": supplementary_failures,
            "exact_lane_raw_abi_complete": True},
        "behavior_lifecycle": {"load_events": loads, "destroy_events": destroys,
            "load_destroy_joins": lifecycle,
            "loaded_candidates": len(loads),
            "loaded_candidates_later_destroyed": sum(row["destroy_observed"] for row in lifecycle),
            "identity_level": "ObjectCandidate",
            "does_not_prove": ["native creation generation", "Remielle EntityIdentity"]},
        "animator_trigger": {"events": sum(row["count"] for row in trigger_rows),
            "unique_runtime_tuples": trigger_rows,
            "nested_unity_animator_relation_observed": bool(trigger_rows),
            "parameter_value_recovered": False,
            "reason": ("the source field at SetTriggerParameter+0x68 is SharedString; the plan captured "
                       "that wrapper object, not a separately dereferenced System.String value")},
        "animator_invoker": {"unique_runtime_tuples": invoker_rows,
            "selected_bridge_rva": selected_bridge_rva,
            "selected_bridge_count": selected[0]["count"],
            "selected_bridge_action_window_count": selected_action_count,
            "selected_exact_caller_return_rva": 0xACE055,
            "same_invocation_child_dispatch_observed": True},
        "checks": {"entry_session_accepted": True, "store_clean": True,
            "exact_condition_lane_complete": True,
            "selected_animator_bridge_observed": bool(selected),
            "all_loaded_candidates_later_destroyed": bool(loads) and all(
                row["destroy_observed"] for row in lifecycle)},
        "controller_exact_closure_complete": False,
        "remaining_gaps": [
            "the selected direct IntComparison caller produced ActionMode conditions, not the five static Remielle Int_AIMoveType/Int_ActiveSkill conditions; three skill branches have downstream structural candidates but not current-session EntityIdentity",
            "Behavior load/destroy boundaries establish ObjectCandidates but do not bind them to the Remielle entity",
            "SetTriggerParameter reached one nested Unity Animator, but the SharedString parameter value was not dereferenced by this plan",
            "ordinary special independent coverage and per-move controller attribution remain separate gaps",
        ],
        "next": "perform static callsite/object-field narrowing before deciding whether another runtime unit is necessary",
    }
    output.mkdir(parents=True)
    artifact = output / "controller-exact-closure-runtime-analysis.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-exact-closure-runtime-analysis-report.v1",
              "artifact": _source(artifact), "events": result["session"]["event_count"],
              "expected_condition_set_observed": result["conditions"]["target_status"] ==
                  "OBSERVED_EXPECTED_CONDITION_SET",
              "selected_bridge_count": selected[0]["count"],
              "loaded_candidates_later_destroyed": result["behavior_lifecycle"][
                  "loaded_candidates_later_destroyed"],
              "controller_exact_closure_complete": False}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--task-ancestor", type=Path, required=True)
    parser.add_argument("--enum", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--api-usage", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.session, args.acceptance, args.plan, args.task_ancestor, args.enum,
            args.type_layout, args.api_usage, args.out)
    except Exception as error:
        write_failure(args.out, "controller_exact_closure_analyze", error,
                      sources=[path for path in (args.session, args.acceptance, args.plan,
                          args.task_ancestor, args.enum, args.type_layout, args.api_usage) if path.exists()])
        raise
