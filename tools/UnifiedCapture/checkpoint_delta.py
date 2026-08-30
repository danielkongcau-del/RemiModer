"""Derive bounded, source-linked counter deltas between capture marks.

The result is a projection, never the evidence original.  Checkpoint snapshots
are explicitly non-atomic, so a delta is bounded by both snapshots' QPC spans
and must not be presented as a perfectly cut per-event trace.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.store import read_manifest


COUNTERS = (
    "callbacks_observed", "records_captured", "records_store_attempted",
    "records_encoded", "filtered_by_plan", "suppressed_by_retention_policy",
)
STORE_COUNTERS = (
    "events_attempted", "events_encoded", "encoded_record_bytes",
    "store_backpressure_events", "sealed_chunks", "sealed_raw_payload_bytes",
    "sealed_file_bytes", "manifest_flushes", "manifest_bytes",
)


def _rows(checkpoint: dict[str, Any], name: str) -> dict[tuple[int, str], dict[str, Any]]:
    return {(int(row["generation"]), row["point"]): row for row in checkpoint.get(name, [])}


def _delta(now: int, prior: int, field: str) -> int:
    if now < prior:
        raise ValueError(f"non-monotonic cumulative counter: {field}: {prior} -> {now}")
    return now - prior


def _retention_keys(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for item in row.get("keys", []):
        parts = item.get("key_parts")
        identity = ("parts:" + json.dumps(parts, sort_keys=True, separators=(",", ":"))
                    if isinstance(parts, list) and parts else
                    f"entry:{int(item['entry_return_address']):016x}")
        if identity in result:
            raise ValueError("duplicate retention key identity")
        result[identity] = item
    return result


def build_deltas(checkpoints: list[dict[str, Any]], *, manifest_complete: bool) -> list[dict[str, Any]]:
    if len(checkpoints) < 2:
        return []
    result = []
    for prior, current in zip(checkpoints, checkpoints[1:]):
        if current["checkpoint_id"] <= prior["checkpoint_id"]:
            raise ValueError("checkpoint ids are not strictly increasing")
        qpc_fields = []
        for label, checkpoint in (("prior", prior), ("current", current)):
            begin, end = checkpoint.get("snapshot_begin_qpc"), checkpoint.get("snapshot_end_qpc")
            if type(begin) is not int or type(end) is not int or begin < 0 or end < begin:
                raise ValueError(f"{label} checkpoint has an invalid QPC interval")
            qpc_fields.append((begin, end))
        if qpc_fields[1][0] < qpc_fields[0][1]:
            raise ValueError("checkpoint QPC intervals overlap or move backwards")
        prior_metrics, current_metrics = _rows(prior, "point_metrics"), _rows(current, "point_metrics")
        prior_loss, current_loss = _rows(prior, "loss"), _rows(current, "loss")
        prior_retention, current_retention = _rows(prior, "retention"), _rows(current, "retention")
        admission_delta = _delta(int(current.get("admission", {}).get("drops", 0)),
                                 int(prior.get("admission", {}).get("drops", 0)), "admission.drops")
        unattributed_delta = _delta(int(current.get("unattributed_storage_loss_events", 0)),
                                    int(prior.get("unattributed_storage_loss_events", 0)),
                                    "unattributed_storage_loss_events")
        points = []
        for key, metrics in sorted(current_metrics.items()):
            baseline = prior_metrics.get(key)
            counter_delta = {field: _delta(int(metrics.get(field, 0)), int((baseline or {}).get(field, 0)),
                                           f"{key}.{field}") for field in COUNTERS}
            loss = current_loss.get(key, {})
            old_loss = prior_loss.get(key, {}) if baseline is not None else {}
            lost_events = _delta(int(loss.get("events", 0)), int(old_loss.get("events", 0)), f"{key}.loss.events")
            reason_delta = {}
            for reason, values in loss.get("reasons", {}).items():
                before = old_loss.get("reasons", {}).get(reason, {})
                events = _delta(int(values.get("events", 0)), int(before.get("events", 0)),
                                f"{key}.loss.{reason}.events")
                if events:
                    reason_delta[reason] = {"events": events,
                        "occurrences": _delta(int(values.get("occurrences", 0)),
                                              int(before.get("occurrences", 0)),
                                              f"{key}.loss.{reason}.occurrences")}
            callers = []
            retained = current_retention.get(key)
            if retained is not None:
                before_keys = _retention_keys(prior_retention.get(key, {}))
                for identity, caller in sorted(_retention_keys(retained).items()):
                    before = before_keys.get(identity, {})
                    address = int(caller["entry_return_address"])
                    change = _delta(int(caller["count"]), int(before.get("count", 0)), f"{key}.caller.{identity}")
                    if change:
                        delta = {"entry_return_address": address, "callbacks": change,
                            "lane": caller.get("lane", "unknown"),
                            "full_records_persisted": _delta(int(caller.get("full_records_persisted", 0)),
                                int(before.get("full_records_persisted", 0)),
                                f"{key}.caller.{identity}.full_records_persisted")}
                        for field in ("key_hash", "key_parts"):
                            if field in caller:
                                delta[field] = caller[field]
                        callers.append(delta)
            if baseline is None:
                integrity = "UNKNOWN_GENERATION_BASELINE_ABSENT"
            elif lost_events or unattributed_delta or admission_delta or not manifest_complete:
                integrity = "UNKNOWN_WITH_INTEGRITY_GAP"
            else:
                integrity = "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS"
            points.append({"generation": key[0], "point": key[1],
                "baseline_checkpoint_contains_generation": baseline is not None,
                "counter_delta": counter_delta, "lost_events": lost_events,
                "loss_reason_delta": reason_delta, "caller_key_deltas": callers,
                "integrity": integrity})
        prior_store, current_store = prior.get("storage", {}), current.get("storage", {})
        store_delta = {field: _delta(int(current_store.get(field, 0)), int(prior_store.get(field, 0)),
                                     f"storage.{field}") for field in STORE_COUNTERS}
        result.append({"from": {"checkpoint_id": prior["checkpoint_id"], "label": prior.get("label"),
                                 "snapshot_begin_qpc": prior["snapshot_begin_qpc"],
                                 "snapshot_end_qpc": prior["snapshot_end_qpc"]},
            "to": {"checkpoint_id": current["checkpoint_id"], "label": current.get("label"),
                    "snapshot_begin_qpc": current["snapshot_begin_qpc"],
                    "snapshot_end_qpc": current["snapshot_end_qpc"]},
            "boundary_semantics": "bounded_non_atomic_cumulative",
            "admission_window_drops": admission_delta,
            "unattributed_storage_loss_events": unattributed_delta,
            "storage_delta": store_delta, "points": points})
    return result


def derive(session: Path, output: Path) -> dict[str, Any]:
    session, output = session.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest_path = session / "session.manifest"
    manifest, errors = read_manifest(manifest_path)
    checkpoints = [row for row in manifest if row.get("kind") == "capture_checkpoint"
                   and row.get("schema") == "uc.CaptureCheckpoint.v1"]
    ended = bool(manifest and manifest[-1].get("kind") == "session_end")
    document = {"schema": "uc.CaptureCheckpointDeltas.v1", "source": {
        "manifest": str(manifest_path), "sha256": file_hash(manifest_path)},
        "manifest_errors": errors, "session_ended": ended,
        "snapshot_warning": "checkpoint boundaries are bounded non-atomic snapshots, not exact event cuts",
        "checkpoint_count": len(checkpoints),
        "intervals": build_deltas(checkpoints, manifest_complete=not errors and ended)}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    return {"ok": True, "output": str(output), "checkpoints": len(checkpoints),
            "intervals": len(document["intervals"]), "manifest_errors": errors}


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser()
    parser.add_argument("session", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = derive(args.session, args.output)
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
