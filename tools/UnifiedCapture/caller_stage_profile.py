"""Profile retained caller counts across linked capture checkpoints.

The output is a prioritization projection.  A caller concentrated in one user
labelled interval is not automatically attributed to a move or character.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(acceptance: dict[str, Any], deltas: dict[str, Any],
          runtime_join: dict[str, Any]) -> dict[str, Any]:
    metadata = {}
    for point in acceptance.get("points", []):
        for caller in point.get("runtime_caller_evidence", []):
            metadata[(point["point"], int(caller["return_address"]))] = caller
    join_rows = {(row["callee_point"], int(row["caller_runtime_function"]["begin_rva"]),
                  int(row["callsite_rva"])): row
                 for row in runtime_join.get("caller_evidence", [])}
    profiles: dict[tuple[str, int], dict[str, Any]] = {}
    action_labels = []
    for ordinal, interval in enumerate(deltas.get("intervals", [])):
        integrity_ok = (interval.get("admission_window_drops", 0) == 0
            and interval.get("unattributed_storage_loss_events", 0) == 0
            and all(row.get("integrity") ==
                    "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS"
                    for row in interval.get("points", [])))
        if not integrity_ok:
            raise ValueError("caller stage profile requires lossless checkpoint intervals")
        label = "PRE_ACTION" if ordinal == 0 else str(interval["from"].get("label"))
        if ordinal:
            action_labels.append(label)
        for point in interval.get("points", []):
            for caller in point.get("caller_key_deltas", []):
                key = (point["point"], int(caller["entry_return_address"]))
                row = profiles.setdefault(key, {"point": key[0], "return_address": key[1],
                    "counts_by_interval": {}, "total_callbacks": 0})
                callbacks = int(caller["callbacks"])
                row["counts_by_interval"][label] = callbacks
                row["total_callbacks"] += callbacks
    output = []
    for key, row in profiles.items():
        caller = metadata.get(key)
        if caller is None:
            raise ValueError(f"checkpoint caller lacks acceptance metadata: {key}")
        action_counts = {label: int(row["counts_by_interval"].get(label, 0))
                         for label in action_labels}
        action_total = sum(action_counts.values())
        active = [label for label, count in action_counts.items() if count]
        dominant = max(action_counts, key=action_counts.get) if action_total else None
        owner = caller.get("caller_runtime_function") or {}
        callsite = caller.get("callsite_rva")
        joined = join_rows.get((row["point"], owner.get("begin_rva"), callsite))
        output.append({**row,
            "module": caller.get("module"),
            "return_rva": caller.get("return_rva"),
            "callsite_rva": callsite,
            "caller_runtime_function": owner or None,
            "callsite_status": caller.get("callsite_status"),
            "action_callbacks": action_total,
            "active_action_intervals": len(active),
            "dominant_action_label": dominant,
            "dominant_action_share_ppm": (
                action_counts[dominant] * 1_000_000 // action_total
                if dominant is not None else 0),
            "exclusive_to_one_action_window": len(active) == 1,
            "logical_owner": joined.get("logical_owner") if joined else None,
            "catalog_matches": joined.get("catalog_matches", []) if joined else [],
            "static_match": joined.get("static_match", False) if joined else False,
        })
    output.sort(key=lambda row: (-int(row["exclusive_to_one_action_window"]),
                                 row["active_action_intervals"],
                                 -row["dominant_action_share_ppm"],
                                 -row["action_callbacks"], row["point"],
                                 row["return_address"]))
    priority = [row for row in output
                if row["exclusive_to_one_action_window"] and row["action_callbacks"] >= 2]
    return {
        "action_labels": action_labels,
        "callers": output,
        "priority_candidates": priority,
        "summary": {
            "retained_caller_keys": len(output),
            "callers_active_in_action_windows": sum(row["action_callbacks"] > 0 for row in output),
            "single_action_window_callers": sum(
                row["exclusive_to_one_action_window"] for row in output),
            "single_action_window_priority_candidates": len(priority),
            "static_matched_callers": sum(row["static_match"] for row in output),
            "catalog_matched_callers": sum(bool(row["catalog_matches"]) for row in output),
        },
    }


def derive(acceptance_path: Path, checkpoint_path: Path, runtime_join_path: Path,
           output: Path) -> dict[str, Any]:
    paths = [Path(value).resolve() for value in
             (acceptance_path, checkpoint_path, runtime_join_path)]
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance, deltas, runtime_join = map(_load, paths)
    if not acceptance.get("accepted"):
        raise ValueError("entry acceptance is not globally accepted")
    analysis = build(acceptance, deltas, runtime_join)
    document = {"schema": "uc.retained-caller-stage-profile.v1",
        "sources": {name: {"path": str(path), "sha256": file_hash(path)}
                    for name, path in zip(("entry_acceptance", "checkpoint_deltas",
                                          "runtime_static_join"), paths)},
        **analysis,
        "boundary_semantics": "bounded non-atomic checkpoint counter deltas",
        "semantic_limits": [
            "A label denotes a broad user action interval, not one move.",
            "Stage concentration is a prioritization signal, not semantic caller identity.",
            "PRE_ACTION is excluded from action-window exclusivity.",
            "Cross-thread causality and entity identity remain unproven.",
        ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    result = {"ok": True, "output": str(output), **document["summary"]}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--checkpoints", type=Path, required=True)
    parser.add_argument("--runtime-join", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.acceptance, args.checkpoints, args.runtime_join, args.out)


if __name__ == "__main__":
    run_main(main)
