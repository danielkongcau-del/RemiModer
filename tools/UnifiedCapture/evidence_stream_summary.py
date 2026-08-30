"""Stream a sealed capture into bounded per-point coverage statistics."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, read_manifest


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def latest_finish(run: Path) -> dict[str, Any]:
    attempts = sorted(run.glob("finish-attempt-*.json"))
    path = attempts[-1] if attempts else run / "finish-result.json"
    return load(path)


def classify(stored: int, loss: int, covered: bool, window: list[int] | None,
             store_clean: bool) -> str:
    if stored and loss:
        return "OBSERVED_WITH_INCOMPLETE_STREAM"
    if loss or not covered or window is None or not store_clean:
        return "UNKNOWN"
    if stored:
        return "OBSERVED"
    return "NOT_OBSERVED_IN_COVERED_WINDOW"


def summarize(run: Path, output: Path) -> dict[str, Any]:
    run, output = run.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    intent = load(run / "intent.json")
    result = load(run / "result.json")
    finish = latest_finish(run)
    report = load(run / "derived" / "report.json")
    plan_path = Path(report["entry_plan"]["path"])
    plan = load(plan_path)
    session = Path(finish["directory"])
    manifest, manifest_errors = read_manifest(session / "session.manifest")
    dictionary_context = event_dictionary_context(session / "session.manifest", manifest)
    generation = result["generation"]
    marks = [row for row in manifest if row.get("kind") == "user_mark"]
    checkpoints = [row for row in manifest if row.get("kind") == "capture_checkpoint"]
    armed = [row["qpc"] for row in marks if row.get("label") == intent["armed_label"]]
    completed = [row["qpc"] for row in marks if row.get("label") == intent["finish_label"]]
    window = None
    if armed and completed:
        begin = max(armed)
        ends = [value for value in completed if value >= begin]
        if ends:
            window = [begin, min(ends)]
    end = next((row for row in reversed(manifest) if row.get("kind") == "session_end"), {})
    loss_rows = {row["point"]: row for row in end.get("loss", [])
                 if row.get("generation") == generation}
    coverage = {row["point"]: row for row in manifest
                if row.get("kind") == "coverage" and row.get("generation") == generation}
    points = {row["id"]: {"activation_events": 0, "window_events": 0,
                           "first_qpc": None, "last_qpc": None,
                           "kinds": Counter(), "threads": set(), "read_values": {},
                           "read_value_sets_truncated": set(), "read_tuples": Counter(),
                           "read_tuple_set_truncated": False, "sample_event_ids": []}
              for row in plan["observations"]}
    chunks = [row for row in manifest if row.get("kind") == "chunk"]
    total_events = 0
    decoded_chunks = []
    for chunk in chunks:
        path = session / chunk["file"]
        header, records = decode_chunk_file(path, dictionary_context=dictionary_context)
        if any(header[key] != chunk[key] for key in
               ("chunk_id", "event_count", "min_event_id", "max_event_id",
                "min_qpc", "max_qpc", "sha256", "crc32c")):
            raise ValueError(f"manifest/chunk mismatch: {path}")
        decoded_chunks.append({"path": str(path), "sha256": file_hash(path),
                               "event_count": header["event_count"]})
        total_events += len(records)
        for _, _, event, _ in records:
            if event.get("generation") != generation:
                continue
            row = points.get(event.get("point"))
            if row is None:
                continue
            row["activation_events"] += 1
            qpc = event["qpc"]
            row["first_qpc"] = qpc if row["first_qpc"] is None else min(row["first_qpc"], qpc)
            row["last_qpc"] = qpc if row["last_qpc"] is None else max(row["last_qpc"], qpc)
            row["kinds"][event.get("kind", "")] += 1
            row["threads"].add(event.get("tid"))
            if window is not None and window[0] <= qpc <= window[1]:
                row["window_events"] += 1
            if len(row["sample_event_ids"]) < 8:
                row["sample_event_ids"].append(event["event_id"])
            values = {read.get("id"): read.get("value") for read in event.get("reads", [])
                      if read.get("status") == 1 and read.get("id") is not None
                      and read.get("value") is not None}
            for read_id, value in values.items():
                value_set = row["read_values"].setdefault(read_id, set())
                if len(value_set) < 65536 or value in value_set:
                    value_set.add(value)
                else:
                    row["read_value_sets_truncated"].add(read_id)
            read_tuple = tuple(sorted(values.items()))
            if read_tuple:
                if len(row["read_tuples"]) < 65536 or read_tuple in row["read_tuples"]:
                    row["read_tuples"][read_tuple] += 1
                else:
                    row["read_tuple_set_truncated"] = True
    store_clean = (finish.get("clean") is True and finish.get("state") == "STOPPED_CLEAN"
                   and end.get("cleanup") == "STOPPED_CLEAN" and not manifest_errors
                   and len(decoded_chunks) == end.get("chunks"))
    output_points = []
    for observation in plan["observations"]:
        point = observation["id"]
        row = points[point]
        loss = loss_rows.get(point, {})
        lost = int(loss.get("events", 0))
        covered = coverage.get(point, {}).get("complete") is True
        stored = row["window_events"] if window is not None else row["activation_events"]
        output_points.append({"point": point,
            "status": classify(stored, lost, covered, window, store_clean),
            "activation_events": row["activation_events"], "window_events": row["window_events"],
            "lost_events": lost, "filtered_by_plan": int(loss.get("filtered_by_plan", 0)),
            "loss_reasons": {reason: int(values.get("events", 0))
                             for reason, values in loss.get("reasons", {}).items()
                             if int(values.get("events", 0))},
            "exact_stream_state": loss.get("exact_stream_state", "UNKNOWN"),
            "coverage_complete": covered, "first_qpc": row["first_qpc"],
            "last_qpc": row["last_qpc"], "kinds": dict(row["kinds"]),
            "thread_count": len(row["threads"]),
            "read_value_distinct": {key: len(values) for key, values in row["read_values"].items()},
            "read_value_sets_truncated": sorted(row["read_value_sets_truncated"]),
            "read_tuple_distinct": len(row["read_tuples"]),
            "read_tuple_set_truncated": row["read_tuple_set_truncated"],
            "top_read_tuples": [{"values": dict(values), "count": count}
                                for values, count in row["read_tuples"].most_common(32)],
            "sample_event_ids": row["sample_event_ids"]})
    summary = {"schema": "uc.streaming-entry-summary.v1", "run": str(run),
        "run_sources": {"plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
                        "finish": {"sha256": file_hash(run / "finish-result.json")}},
        "session": str(session), "session_id": result["session_id"], "generation": generation,
        "marked_window": window, "store_clean": store_clean, "manifest_errors": manifest_errors,
        "capture_checkpoints": [{"checkpoint_id": row.get("checkpoint_id"), "label": row.get("label"),
                                 "snapshot_begin_qpc": row.get("snapshot_begin_qpc"),
                                 "snapshot_end_qpc": row.get("snapshot_end_qpc"),
                                 "snapshot_atomic": row.get("snapshot_atomic")}
                                for row in checkpoints],
        "chunks_declared": len(chunks), "chunks_decoded": len(decoded_chunks),
        "total_stored_events_all_generations": total_events,
        "admission_window_drops": int(finish.get("admission_window_drops", 0)),
        "points": output_points,
        "totals": {"observations": len(output_points),
                   "observed": sum(row["status"].startswith("OBSERVED") for row in output_points),
                   "lossless_points": sum(row["lost_events"] == 0 for row in output_points),
                   "lossy_points": sum(row["lost_events"] > 0 for row in output_points),
                   "stored_activation_events": sum(row["activation_events"] for row in output_points),
                   "stored_window_events": sum(row["window_events"] for row in output_points),
                   "lost_events": sum(row["lost_events"] for row in output_points)}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(summary))
    print(json.dumps({"output": str(output), **summary["totals"],
                      "store_clean": store_clean}, ensure_ascii=False))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(summarize, args.run, args.out)
