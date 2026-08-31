"""Derive bounded controller-frontier joins from one sealed final runtime run.

The projection keeps process addresses, object candidates, and gameplay identity
separate.  In particular, an action-window correlation or a common Animator
receiver is not promoted to a serialized task or entity identity.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, read_manifest


TASK_TYPES = {
    "SetBoolParameter": 34455,
    "SetIntegerParameter": 34459,
    "SetTriggerParameter": 41564,
}
TASK_PREFIXES = tuple(f"{name}." for name in TASK_TYPES)
UNITY_SELECTED_PREFIX = "UnityPlayer."


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _values(event: dict[str, Any]) -> dict[str, int]:
    return {
        str(row["id"]): int(row["value"])
        for row in event.get("reads", [])
        if row.get("status") == 1 and row.get("id") is not None
        and type(row.get("value")) is int
    }


def _read_rows(event: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row["id"]): row
        for row in event.get("reads", [])
        if row.get("id") is not None
    }


def _decode_system_string(blob: bytes, read: dict[str, Any] | None) -> dict[str, Any]:
    """Decode the captured IL2CPP System.String object without dereferencing later."""
    if read is None:
        return {"status": "READ_NOT_PRESENT", "value": None}
    if read.get("status") != 1:
        return {"status": f"READ_STATUS_{read.get('status')}", "value": None}
    begin, size = int(read.get("offset", 0)), int(read.get("length", 0))
    block = blob[begin:begin + size]
    if len(block) < 20:
        return {"status": "BLOCK_TOO_SHORT", "value": None}
    count = int.from_bytes(block[16:20], "little", signed=True)
    required = 20 + count * 2
    if count < 0 or required > len(block):
        return {"status": "INVALID_STRING_LENGTH", "value": None,
                "declared_characters": count, "captured_bytes": len(block)}
    try:
        value = block[20:required].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        return {"status": "INVALID_UTF16", "value": None,
                "declared_characters": count}
    return {"status": "OK", "value": value,
            "declared_characters": count}


def _family(point: str) -> str:
    return point.split(".", 1)[0]


def _intervals(deltas: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for ordinal, row in enumerate(deltas.get("intervals", []), 1):
        begin = int(row["from"]["snapshot_end_qpc"])
        end = int(row["to"]["snapshot_begin_qpc"])
        if end < begin:
            raise ValueError("checkpoint stable interiors move backwards")
        lost = sum(int(item.get("lost_events", 0)) for item in row.get("points", []))
        complete = (
            int(row.get("admission_window_drops", 0)) == 0
            and int(row.get("unattributed_storage_loss_events", 0)) == 0
            and lost == 0
            and all(item.get("integrity") ==
                    "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS"
                    for item in row.get("points", []))
        )
        result.append({
            "ordinal": ordinal,
            "from": row["from"].get("label"),
            "to": row["to"].get("label"),
            "label": f'{row["from"].get("label")}->{row["to"].get("label")}',
            "begin_qpc_exclusive": begin,
            "end_qpc_exclusive": end,
            "complete": complete,
            "lost_events": lost,
        })
    return result


def _interval_for(qpc: int, intervals: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((row for row in intervals
                 if row["begin_qpc_exclusive"] < qpc < row["end_qpc_exclusive"]), None)


def _counter_rows(counter: Counter, names: tuple[str, ...]) -> list[dict[str, Any]]:
    rows = []
    for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        values = key if isinstance(key, tuple) else (key,)
        rows.append({**dict(zip(names, values)), "count": count})
    return rows


def _static_task_index(path: Path | None) -> dict[tuple[int, int], list[dict[str, Any]]]:
    if path is None:
        return {}
    result: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in _load(path):
        record = row.get("currentParameterRecord")
        if not isinstance(record, list) or not record or type(record[0]) is not int:
            continue
        key = (int(row["nativeTypeIndex"]), int(record[0]))
        result[key].append({
            "root_or_referenced_tree": row.get("abTree"),
            "runtime_task_index": row.get("runtimeIndex"),
            "serialized_task_index": row.get("abIndex"),
            "parameter_name": row.get("parameterName"),
        })
    return result


def _ability_parameter_names(path: Path | None) -> dict[int, list[str]]:
    if path is None:
        return {}
    document = _load(path)
    result: dict[int, set[str]] = defaultdict(set)
    for row in document.get("exactJoins", {}).get("controllerParameters", []):
        for target in row.get("targets", []):
            value = target.get("id")
            if type(value) is int:
                result[value].add(str(row.get("value")))
    return {key: sorted(values) for key, values in result.items()}


def analyze(run: Path, output: Path, static_task_links: Path | None,
            ability_joins: Path | None) -> dict[str, Any]:
    run, output = run.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    summary_path = run / "streaming-summary.json"
    delta_path = run / "checkpoint-deltas.json"
    summary = _load(summary_path)
    deltas = _load(delta_path)
    if summary.get("store_clean") is not True:
        raise ValueError("sealed stream is not clean")
    intervals = _intervals(deltas)
    if not intervals or not all(row["complete"] for row in intervals):
        raise ValueError("checkpoint intervals are incomplete")
    session = Path(summary["session"])
    manifest_path = session / "session.manifest"
    manifest, manifest_errors = read_manifest(manifest_path)
    if manifest_errors:
        raise ValueError(f"manifest errors: {manifest_errors}")
    context = event_dictionary_context(manifest_path, manifest)
    events: list[dict[str, Any]] = []
    for chunk in manifest:
        if chunk.get("kind") != "chunk":
            continue
        _, records = decode_chunk_file(session / chunk["file"],
                                       dictionary_context=context)
        for _, _, event, blob in records:
            if event.get("generation") != int(summary["generation"]):
                continue
            event = dict(event)
            event["_record_blob"] = blob
            events.append(event)
    events.sort(key=lambda row: int(row["event_id"]))

    static_index = _static_task_index(static_task_links)
    ability_names = _ability_parameter_names(ability_joins)
    by_interval: dict[str, dict[str, Any]] = {}
    for interval in intervals:
        by_interval[interval["label"]] = {
            "event_count": 0,
            "points": Counter(),
            "selected_calls": Counter(),
            "receivers": Counter(),
            "task_families": Counter(),
            "stage_objects": Counter(),
        }

    try_load: dict[int, dict[str, Any]] = {}
    completed: dict[int, dict[str, Any]] = {}
    destroyed: list[dict[str, Any]] = []
    task_events: list[dict[str, Any]] = []
    selected_events: list[dict[str, Any]] = []
    receiver_profiles: dict[int, dict[str, Any]] = defaultdict(lambda: {
        "task_families": Counter(), "task_addresses": set(),
        "consumer_calls": Counter(), "intervals": Counter(),
    })

    for event in events:
        point = str(event.get("point", ""))
        values = _values(event)
        interval = _interval_for(int(event["qpc"]), intervals)
        label = interval["label"] if interval else None
        if label:
            bucket = by_interval[label]
            bucket["event_count"] += 1
            bucket["points"][point] += 1
        if point.startswith("BehaviorManager.TryLoadBehavior"):
            try_load[values["behavior"]] = {"event": event, "values": values,
                                             "interval": label}
        elif point.startswith("BehaviorManager.LoadBehaviorComplete"):
            reads = _read_rows(event)
            completed[values["behavior"]] = {
                "event": event,
                "values": values,
                "interval": label,
                "behavior_name": _decode_system_string(
                    event["_record_blob"], reads.get("behavior-name-object")),
                "external_name": _decode_system_string(
                    event["_record_blob"], reads.get("external-name-object")),
            }
        elif point.startswith("BehaviorManager.DestroyBehavior"):
            destroyed.append({"event": event, "values": values, "interval": label})
        if point.startswith(TASK_PREFIXES):
            family = _family(point)
            receiver = values.get("animator-native-receiver")
            row = {"event": event, "values": values, "interval": label,
                   "family": family, "native_type_index": TASK_TYPES[family],
                   "receiver": receiver}
            task_events.append(row)
            if label:
                by_interval[label]["task_families"][family] += 1
            if receiver:
                profile = receiver_profiles[receiver]
                profile["task_families"][family] += 1
                if values.get("raw-rcx"):
                    profile["task_addresses"].add(values["raw-rcx"])
                if label:
                    profile["intervals"][label] += 1
        if (point.startswith(UNITY_SELECTED_PREFIX)
                and ".selected-parameters" in point):
            operation = point.split(".", 2)[1]
            receiver = values.get("receiver")
            parameter = values.get("parameter-id")
            selected_events.append({"event": event, "values": values,
                                    "interval": label, "operation": operation})
            if label:
                bucket = by_interval[label]
                bucket["selected_calls"][(operation, parameter, receiver,
                                           values.get("value-gpr"))] += 1
                bucket["receivers"][receiver] += 1
            if receiver:
                profile = receiver_profiles[receiver]
                profile["consumer_calls"][(operation, parameter)] += 1
                if label:
                    profile["intervals"][label] += 1
        if "AnimatorStage." in point and label:
            by_interval[label]["stage_objects"][(point, values.get("stage-object"))] += 1

    next_by_id = {int(row["event_id"]): row for row in events}
    adjacency = []
    for task in task_events:
        event = task["event"]
        successor = next_by_id.get(int(event["event_id"]) + 1)
        if successor is None or successor.get("tid") != event.get("tid"):
            continue
        successor_point = str(successor.get("point", ""))
        if not (successor_point.startswith(UNITY_SELECTED_PREFIX)
                and ".selected-parameters" in successor_point):
            continue
        successor_values = _values(successor)
        if task["receiver"] != successor_values.get("receiver"):
            continue
        parameter = successor_values.get("parameter-id")
        static_candidates = static_index.get((task["native_type_index"], parameter), [])
        adjacency.append({
            "task_event_id": int(event["event_id"]),
            "consumer_event_id": int(successor["event_id"]),
            "same_thread_consecutive_stored_events": True,
            "task_family": task["family"],
            "native_type_index": task["native_type_index"],
            "task_address": task["values"].get("raw-rcx"),
            "receiver": task["receiver"],
            "consumer_operation": successor_point.split(".", 2)[1],
            "parameter_id": parameter,
            "parameter_names_from_game_assets": ability_names.get(parameter, []),
            "raw_value_gpr": successor_values.get("value-gpr"),
            "interval": task["interval"],
            "static_remielle_task_candidates": static_candidates,
        })

    lifetimes = []
    for behavior, load in sorted(try_load.items(), key=lambda item: item[1]["event"]["qpc"]):
        complete = completed.get(behavior)
        ends = [row for row in destroyed if row["values"].get("behavior") == behavior]
        lifetimes.append({
            "behavior_address": behavior,
            "entity_id": load["values"].get("entity-id"),
            "load_event_id": int(load["event"]["event_id"]),
            "load_interval": load["interval"],
            "complete_event_id": (int(complete["event"]["event_id"])
                                  if complete else None),
            "behavior_tree_address": (complete["values"].get("behavior-tree")
                                      if complete else None),
            "behavior_owner_address": (complete["values"].get("behavior-owner")
                                       if complete else None),
            "behavior_name": (complete["behavior_name"] if complete else
                              {"status": "LOAD_NOT_COMPLETED", "value": None}),
            "external_behavior_name": (complete["external_name"] if complete else
                                       {"status": "LOAD_NOT_COMPLETED", "value": None}),
            "destroy_events": [{"event_id": int(row["event"]["event_id"]),
                                "qpc": int(row["event"]["qpc"]),
                                "execution_status": row["values"].get("execution-status"),
                                "interval": row["interval"]} for row in ends],
            "end_boundary": "OBSERVED" if ends else "UNKNOWN_AFTER_CAPTURE_END",
        })
    by_entity: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in lifetimes:
        by_entity[int(row["entity_id"])].append(row)
    multi_behavior_entities = [{"entity_id": entity,
              "behavior_addresses": [row["behavior_address"] for row in rows],
              "behavior_tree_addresses": [row["behavior_tree_address"] for row in rows],
              "distinct_behavior_instances": len({row["behavior_address"] for row in rows})}
             for entity, rows in sorted(by_entity.items()) if len(rows) > 1]
    remielle_lifetimes = [
        row for row in lifetimes
        if "RemielleOrigin" in str(row["external_behavior_name"].get("value") or "")
    ]
    remielle_entities = sorted({int(row["entity_id"]) for row in remielle_lifetimes})

    profiles = []
    for receiver, row in sorted(receiver_profiles.items(),
                                key=lambda item: (-sum(item[1]["consumer_calls"].values()),
                                                  item[0])):
        families = sorted(row["task_families"])
        profiles.append({
            "receiver": receiver,
            "task_families": dict(sorted(row["task_families"].items())),
            "task_addresses": sorted(row["task_addresses"]),
            "consumer_calls": _counter_rows(row["consumer_calls"],
                                             ("operation", "parameter_id")),
            "consumer_call_count": sum(row["consumer_calls"].values()),
            "intervals": dict(sorted(row["intervals"].items())),
            "task_to_consumer_address_join": bool(families and row["consumer_calls"]),
            "all_three_task_families": set(families) == set(TASK_TYPES),
        })

    windows = []
    for interval in intervals:
        row = by_interval[interval["label"]]
        windows.append({
            **interval,
            "event_count": row["event_count"],
            "point_counts": dict(sorted(row["points"].items())),
            "selected_parameter_calls": _counter_rows(
                row["selected_calls"],
                ("operation", "parameter_id", "receiver", "raw_value_gpr")),
            "receiver_counts": _counter_rows(row["receivers"], ("receiver",)),
            "task_family_counts": dict(sorted(row["task_families"].items())),
            "animator_stage_object_counts": _counter_rows(
                row["stage_objects"], ("point", "stage_object")),
        })

    unmatched_destroy = [row for row in destroyed
                         if row["values"].get("behavior") not in try_load]
    cross_family = [row["receiver"] for row in profiles if row["all_three_task_families"]]
    document = {
        "schema": "uc.controller-final-runtime-analysis.v1",
        "sources": {
            "stream_summary": {"path": str(summary_path), "sha256": file_hash(summary_path)},
            "checkpoint_deltas": {"path": str(delta_path), "sha256": file_hash(delta_path)},
            "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
            **({"static_task_links": {"path": str(static_task_links.resolve()),
                                      "sha256": file_hash(static_task_links)}}
               if static_task_links else {}),
            **({"ability_parameter_joins": {"path": str(ability_joins.resolve()),
                                            "sha256": file_hash(ability_joins)}}
               if ability_joins else {}),
        },
        "session_id": summary["session_id"],
        "generation": int(summary["generation"]),
        "integrity": {"store_clean": True, "manifest_errors": [],
                      "complete_checkpoint_intervals": len(intervals),
                      "lost_events": 0},
        "behavior_lifetimes": lifetimes,
        "remielle_origin_behavior_lifetimes": remielle_lifetimes,
        "remielle_origin_entity_id_candidates": remielle_entities,
        "multi_behavior_entity_id_evidence": multi_behavior_entities,
        "destroyed_preexisting_or_unobserved_instances": [
            {"behavior_address": row["values"].get("behavior"),
             "event_id": int(row["event"]["event_id"]),
             "execution_status": row["values"].get("execution-status"),
             "interval": row["interval"]} for row in unmatched_destroy],
        "task_consumer_adjacency": adjacency,
        "receiver_profiles": profiles,
        "unique_all_three_task_family_receiver_candidates": cross_family,
        "action_windows": windows,
        "summary": {
            "stored_events": len(events),
            "behavior_loads": len(try_load),
            "behavior_completions": len(completed),
            "loaded_behaviors_with_destroy": sum(bool(row["destroy_events"])
                                                 for row in lifetimes),
            "destroyed_preexisting_or_unobserved": len(unmatched_destroy),
            "multi_behavior_entity_ids": len(multi_behavior_entities),
            "decoded_behavior_names": sum(
                row["behavior_name"].get("status") == "OK" for row in lifetimes),
            "decoded_external_behavior_names": sum(
                row["external_behavior_name"].get("status") == "OK" for row in lifetimes),
            "remielle_origin_behavior_lifetimes": len(remielle_lifetimes),
            "remielle_origin_entity_id_candidates": len(remielle_entities),
            "parameter_task_samples": len(task_events),
            "same_thread_consecutive_task_consumer_joins": len(adjacency),
            "receiver_profiles": len(profiles),
            "unique_all_three_task_family_receivers": len(cross_family),
            "selected_parameter_calls": len(selected_events),
            "checkpoint_intervals": len(intervals),
        },
        "semantic_limits": [
            "ObservedAddress equality is not ObjectInstance or EntityIdentity proof.",
            "One entity ID may own multiple distinct Behavior instances; address multiplicity alone is not entity lifetime reuse.",
            "A checkpoint interval is a user action group, not proof that every event in it belongs to one move.",
            "Consecutive stored events on one thread prove bounded temporal adjacency, not a native call edge.",
            "The final plan did not capture TaskExecutor tree-to-task membership in this process; current task addresses are not promoted to serialized Remielle task identities.",
            "Animator stage-object addresses are retained separately from Animator receiver addresses unless an independent native field path proves the join.",
            "raw_value_gpr is preserved as register evidence and is not interpreted as a float argument.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    print(json.dumps({"ok": True, "output": str(output), **document["summary"]},
                     ensure_ascii=False))
    return document


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--static-task-links", type=Path)
    parser.add_argument("--ability-joins", type=Path)
    args = parser.parse_args()
    return analyze(args.run, args.out, args.static_task_links, args.ability_joins)


if __name__ == "__main__":
    run_main(main)
