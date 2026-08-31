"""Derive bounded field and same-address lifecycle evidence from a sealed run.

This projection deliberately stops at observed addresses.  Matching an address
across callbacks proves an address-level relationship in the captured process;
it does not by itself prove a serialized object, entity, or gameplay identity.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Iterable

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, read_manifest


TASK_PREFIXES = (
    "SetBoolParameter.",
    "SetIntegerParameter.",
    "SetTriggerParameter.",
)
ECS_PREFIX = "ODKPBBAJAEG."
MAX_DISTINCT_VALUES = 256


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _stream_summary_path(run: Path) -> Path:
    for name in ("streaming-summary.json", "stream-summary.json"):
        candidate = run / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"no streaming summary in {run}; expected streaming-summary.json or stream-summary.json")


def _method(point: str) -> str:
    stem = point.split("@", 1)[0]
    if stem.startswith(ECS_PREFIX):
        return stem[len(ECS_PREFIX):]
    return stem.rsplit(".", 1)[-1]


def _family(point: str) -> str:
    stem = point.split("@", 1)[0]
    if stem.startswith(ECS_PREFIX):
        return ECS_PREFIX[:-1]
    return stem.rsplit(".", 1)[0]


def _values(event: dict[str, Any]) -> dict[str, int]:
    return {
        row["id"]: int(row["value"])
        for row in event.get("reads", [])
        if row.get("status") == 1 and row.get("id") is not None
        and type(row.get("value")) is int
    }


def stable_intervals(checkpoint_deltas: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for ordinal, row in enumerate(checkpoint_deltas.get("intervals", []), 1):
        begin = int(row["from"]["snapshot_end_qpc"])
        end = int(row["to"]["snapshot_begin_qpc"])
        if end < begin:
            raise ValueError("checkpoint stable interiors overlap or move backwards")
        point_loss = sum(int(item.get("lost_events", 0)) for item in row.get("points", []))
        complete = (
            row.get("admission_window_drops", 0) == 0
            and row.get("unattributed_storage_loss_events", 0) == 0
            and point_loss == 0
            and all(item.get("integrity") ==
                    "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS"
                    for item in row.get("points", []))
        )
        result.append({
            "ordinal": ordinal,
            "label": f'{row["from"].get("label")}->{row["to"].get("label")}',
            "begin_qpc_exclusive": begin,
            "end_qpc_exclusive": end,
            "complete": complete,
            "admission_window_drops": int(row.get("admission_window_drops", 0)),
            "lost_events": point_loss,
            "unattributed_storage_loss_events": int(
                row.get("unattributed_storage_loss_events", 0)),
        })
    return result


def _interval_for(qpc: int, intervals: list[dict[str, Any]]) -> str | None:
    for row in intervals:
        if row["begin_qpc_exclusive"] < qpc < row["end_qpc_exclusive"]:
            return row["label"]
    return None


def analyze_events(events: Iterable[dict[str, Any]], intervals: list[dict[str, Any]],
                   generation: int) -> dict[str, Any]:
    candidates: dict[tuple[str, int], dict[str, Any]] = {}
    excluded_boundary_events = 0
    selected_events = 0

    for event in events:
        if event.get("generation") != generation:
            continue
        point = str(event.get("point", ""))
        if not (point.startswith(TASK_PREFIXES) or point.startswith(ECS_PREFIX)):
            continue
        values = _values(event)
        address = values.get("raw-rcx")
        if address is None:
            continue
        selected_events += 1
        stage = _interval_for(int(event["qpc"]), intervals)
        if stage is None:
            excluded_boundary_events += 1
        group = "ecs-system" if point.startswith(ECS_PREFIX) else "parameter-task"
        identity = (f"{group}:{_family(point)}", address)
        row = candidates.setdefault(identity, {
            "candidate_kind": group,
            "family": _family(point),
            "observed_address": address,
            "event_count": 0,
            "first_qpc": None,
            "last_qpc": None,
            "methods": Counter(),
            "stages": Counter(),
            "field_values": defaultdict(set),
        })
        row["event_count"] += 1
        qpc = int(event["qpc"])
        row["first_qpc"] = qpc if row["first_qpc"] is None else min(row["first_qpc"], qpc)
        row["last_qpc"] = qpc if row["last_qpc"] is None else max(row["last_qpc"], qpc)
        row["methods"][_method(point)] += 1
        if stage is not None:
            row["stages"][stage] += 1
        for name, value in values.items():
            if len(row["field_values"][name]) < MAX_DISTINCT_VALUES:
                row["field_values"][name].add(value)

    output = []
    for row in candidates.values():
        methods = dict(sorted(row["methods"].items()))
        field_values = {name: sorted(values)
                        for name, values in sorted(row["field_values"].items())}
        output.append({
            "candidate_kind": row["candidate_kind"],
            "family": row["family"],
            "observed_address": row["observed_address"],
            "event_count": row["event_count"],
            "first_qpc": row["first_qpc"],
            "last_qpc": row["last_qpc"],
            "methods": methods,
            "stages": dict(sorted(row["stages"].items())),
            "field_values": field_values,
            "phase_evidence": {
                "start_and_update": "OnStart" in methods and "OnUpdate" in methods,
                "reset_observed": "OnReset" in methods,
                "complete_ecs_lifecycle": all(name in methods for name in
                    (".ctor", "CreateFilters", "Start", "Update", "OnDestroy")),
                "end_boundary_unknown": (
                    row["candidate_kind"] == "ecs-system" and "OnDestroy" not in methods),
            },
        })
    output.sort(key=lambda row: (row["candidate_kind"], row["family"],
                                 row["observed_address"]))
    tasks = [row for row in output if row["candidate_kind"] == "parameter-task"]
    ecs = [row for row in output if row["candidate_kind"] == "ecs-system"]
    return {
        "selected_events": selected_events,
        "events_excluded_at_checkpoint_boundaries": excluded_boundary_events,
        "candidates": output,
        "summary": {
            "parameter_task_address_candidates": len(tasks),
            "parameter_task_start_update_same_address": sum(
                row["phase_evidence"]["start_and_update"] for row in tasks),
            "parameter_task_reset_observed": sum(
                row["phase_evidence"]["reset_observed"] for row in tasks),
            "ecs_system_address_candidates": len(ecs),
            "ecs_complete_lifecycles": sum(
                row["phase_evidence"]["complete_ecs_lifecycle"] for row in ecs),
            "ecs_open_end_boundary": sum(
                row["phase_evidence"]["end_boundary_unknown"] for row in ecs),
        },
    }


def derive(run: Path, output: Path) -> dict[str, Any]:
    run, output = run.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    summary_path = _stream_summary_path(run)
    delta_path = run / "checkpoint-deltas.json"
    summary = _load(summary_path)
    deltas = _load(delta_path)
    if not summary.get("store_clean"):
        raise ValueError("sealed stream is not clean")
    intervals = stable_intervals(deltas)
    if not intervals or not all(row["complete"] for row in intervals):
        raise ValueError("checkpoint intervals are incomplete")
    session = Path(summary["session"])
    manifest_path = session / "session.manifest"
    manifest, errors = read_manifest(manifest_path)
    if errors:
        raise ValueError(f"manifest errors: {errors}")
    context = event_dictionary_context(manifest_path, manifest)

    def events():
        for chunk in manifest:
            if chunk.get("kind") != "chunk":
                continue
            _, records = decode_chunk_file(session / chunk["file"],
                                           dictionary_context=context)
            for _, _, event, _ in records:
                yield event

    analysis = analyze_events(events(), intervals, int(summary["generation"]))
    document = {
        "schema": "uc.controller-field-lifecycle-analysis.v1",
        "sources": {
            "stream_summary": {"path": str(summary_path), "sha256": file_hash(summary_path)},
            "checkpoint_deltas": {"path": str(delta_path), "sha256": file_hash(delta_path)},
            "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        },
        "session_id": summary["session_id"],
        "generation": int(summary["generation"]),
        "interval_semantics": (
            "Only the stable interior after the prior checkpoint snapshot and before "
            "the next checkpoint snapshot is assigned to a stage."),
        "intervals": intervals,
        **analysis,
        "semantic_limits": [
            "ObservedAddress equality is not ObjectInstance or EntityIdentity proof.",
            "A lifecycle ending outside the covered window has an unknown end boundary.",
            "Stage labels delimit user action groups and do not attribute an event to one move.",
            "Field names come from the source-bound CapturePlan; values remain raw process data.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    result = {"ok": True, "output": str(output), **document["summary"],
              "selected_events": document["selected_events"]}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.run, args.out)


if __name__ == "__main__":
    run_main(main)
