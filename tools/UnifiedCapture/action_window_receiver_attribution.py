"""Bound action windows to the strongest available Remielle receiver evidence.

The join deliberately distinguishes a direct consecutive TaskExecutor event
from later/earlier traffic that merely uses the same raw receiver address.
Checkpoint labels are preserved as user annotations, not promoted to native
move identities.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_ANALYSIS = ROOT / "extracted/analysis/controller-final-runtime-live-20260831-p40972-v1/analysis/controller-final-runtime-analysis-v3.json"
DEFAULT_IDENTITY = ROOT / "extracted/analysis/controller-final-identity-join-20260831-v1/controller-final-identity-join.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def build(analysis_path: Path, identity_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    analysis = _load(analysis_path)
    identity = _load(identity_path)
    if analysis.get("session_id") != identity.get("session_id"):
        raise ValueError("analysis and identity join sessions differ")
    if analysis.get("generation") != identity.get("generation"):
        raise ValueError("analysis and identity join generations differ")
    integrity = analysis.get("integrity", {})
    if not all(window.get("complete") and window.get("lost_events") == 0
               for window in analysis.get("action_windows", [])):
        raise ValueError("action windows are not all complete and lossless")
    if (integrity.get("store_clean") is not True
            or integrity.get("lost_events") != 0
            or integrity.get("manifest_errors")):
        raise ValueError("runtime evidence store is not clean")
    receiver = int(identity["identity_chain"]["animator_receiver_candidate"]["address"])
    direct = Counter(
        row["interval"] for row in analysis.get("task_consumer_adjacency", [])
        if int(row.get("receiver", -1)) == receiver
        and row.get("same_thread_consecutive_stored_events") is True
    )
    windows = []
    for window in analysis.get("action_windows", []):
        calls = [row for row in window.get("selected_parameter_calls", [])
                 if int(row.get("receiver", -1)) == receiver]
        same_address_calls = sum(int(row["count"]) for row in calls)
        direct_joins = direct.get(window["label"], 0)
        if direct_joins:
            level = "DIRECT_REMIELLE_TASK_TO_CONSUMER_EVENTS"
        elif same_address_calls:
            level = "SAME_ADDRESS_RECEIVER_ACTIVITY_ONLY"
        else:
            level = "NO_JOINED_RECEIVER_ACTIVITY"
        windows.append({
            "ordinal": window["ordinal"],
            "checkpoint_from": window["from"],
            "checkpoint_to": window["to"],
            "user_annotated_interval": window["label"],
            "begin_qpc_exclusive": window["begin_qpc_exclusive"],
            "end_qpc_exclusive": window["end_qpc_exclusive"],
            "complete": window["complete"],
            "lost_events": window["lost_events"],
            "all_selected_event_count": window["event_count"],
            "all_stage_event_count": sum(int(row["count"]) for row in window.get("animator_stage_object_counts", [])),
            "attribution_level": level,
            "direct_same_thread_consecutive_task_consumer_events": direct_joins,
            "same_address_receiver_selected_calls": same_address_calls,
            "same_address_receiver_call_groups": calls,
            "negative_claim_allowed": False,
        })
    counts = Counter(row["attribution_level"] for row in windows)
    artifact = {
        "schema": "uc.action-window-receiver-attribution.v1",
        "session_id": analysis["session_id"],
        "generation": analysis["generation"],
        "sources": {"runtime_analysis": _source(analysis_path), "identity_join": _source(identity_path)},
        "receiver_candidate": {
            "address": receiver,
            "identity_level": "ObservedAddress/ObjectCandidate",
            "direct_task_join_count": sum(direct.values()),
            "direct_task_join_intervals": dict(sorted(direct.items())),
        },
        "summary": {
            "windows": len(windows),
            "complete_lossless_windows": sum(row["complete"] and row["lost_events"] == 0 for row in windows),
            "attribution_level_counts": dict(sorted(counts.items())),
            "windows_with_direct_remielle_task_consumer_events": sum(
                row["direct_same_thread_consecutive_task_consumer_events"] > 0 for row in windows),
            "windows_with_same_address_receiver_activity": sum(
                row["same_address_receiver_selected_calls"] > 0 for row in windows),
        },
        "bounded_conclusions": [
            "one marked interval contains direct same-thread consecutive Remielle TaskExecutor-to-consumer events",
            "other positive intervals prove only traffic on the same raw receiver address",
            "checkpoint labels are user annotations and do not prove every enclosed event belongs to that move",
            "zero joined receiver traffic cannot prove the annotated move did not execute",
            "raw GPR payloads for bool/float calls are preserved without semantic value interpretation",
            "stage events remain all-scene context because this session does not bind their stage objects to the receiver instance",
        ],
        "windows": windows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "action-window-receiver-attribution.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.action-window-receiver-attribution-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": artifact["summary"],
        "complete_per_move_attribution": False,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, default=DEFAULT_ANALYSIS)
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.analysis.resolve(), args.identity.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "action_window_receiver_attribution", error, {
            "analysis": str(args.analysis), "identity": str(args.identity)
        })
        raise


if __name__ == "__main__":
    run_main(main)
