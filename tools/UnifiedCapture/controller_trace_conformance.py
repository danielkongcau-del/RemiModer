"""Evaluate existing action windows against non-speculative evidence rules.

No replacement controller is executed.  A MATCH requires a direct same-thread
Remielle Task-to-consumer witness already present in the source evidence.
Same-address activity and zero traffic remain UNKNOWN because neither proves a
causal relation nor non-execution.  Setup/teardown windows are NOT_APPLICABLE.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


VERDICTS = {"MATCH", "MISMATCH", "UNKNOWN", "NOT_APPLICABLE"}
NON_ACTION_TOKENS = (
    "ENTRY_UNIT_ARMED", "PRE_TRIAL_ARMED", "BASELINE",
    "TRIAL_EXIT_COMPLETE", "ENTRY_UNIT_ACTION_COMPLETE",
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def classify_window(window: dict[str, Any]) -> tuple[str, str]:
    label = str(window["user_annotated_interval"])
    if not window.get("complete") or int(window.get("lost_events", 0)) != 0:
        return "MISMATCH", "window integrity contract failed"
    endpoints = label.split("->")
    if endpoints and all(any(token in endpoint for token in NON_ACTION_TOKENS)
                         for endpoint in endpoints):
        return "NOT_APPLICABLE", "setup/teardown annotation has no action claim"
    direct = int(window.get("direct_same_thread_consecutive_task_consumer_events", 0))
    if direct > 0:
        return "MATCH", "direct same-thread Remielle Task-to-consumer witness exists"
    if window.get("attribution_level") == "SAME_ADDRESS_RECEIVER_ACTIVITY_ONLY":
        return "UNKNOWN", "same-address receiver activity is not a causal identity proof"
    return "UNKNOWN", "no sufficient witness; zero traffic is not a negative behavior claim"


def analyze(model: dict[str, Any], windows: dict[str, Any],
            model_source: dict[str, Any], windows_source: dict[str, Any]) -> dict[str, Any]:
    if model.get("schema") != "uc.controller-evidence-model.v1":
        raise ValueError("unsupported controller evidence model")
    if model["execution_contract"].get("executable") is not False:
        raise ValueError("trace conformance must not execute a replacement controller")
    if windows.get("schema") != "uc.action-window-receiver-attribution.v1":
        raise ValueError("unsupported action-window attribution")
    rows = []
    for window in windows["windows"]:
        verdict, reason = classify_window(window)
        if verdict not in VERDICTS:
            raise AssertionError(verdict)
        rows.append({
            "ordinal": int(window["ordinal"]),
            "user_annotation": window["user_annotated_interval"],
            "annotation_authority": "USER_CHECKPOINT_LABEL_ONLY",
            "covered_lossless": bool(window["complete"]
                                      and int(window["lost_events"]) == 0),
            "attribution_level": window["attribution_level"],
            "direct_same_thread_consecutive_task_consumer_events": int(
                window["direct_same_thread_consecutive_task_consumer_events"]),
            "same_address_receiver_selected_calls": int(
                window["same_address_receiver_selected_calls"]),
            "verdict": verdict,
            "reason": reason,
        })
    counts = {verdict: sum(row["verdict"] == verdict for row in rows)
              for verdict in sorted(VERDICTS)}
    return {
        "schema": "uc.controller-trace-conformance.v1",
        "sources": {"evidence_model": model_source,
                    "action_window_attribution": windows_source},
        "method": {
            "replacement_controller_executed": False,
            "semantic_prediction_performed": False,
            "direct_witness_required_for_match": True,
            "same_address_activity_sufficient_for_match": False,
            "zero_traffic_sufficient_for_mismatch": False,
        },
        "windows": rows,
        "summary": {
            "windows": len(rows),
            "lossless_windows": sum(row["covered_lossless"] for row in rows),
            "verdict_counts": counts,
            "definition_claims_changed": 0,
            "core_blockers_created": 0,
        },
        "acceptance": {
            "source_windows_integrity_complete": all(row["covered_lossless"]
                                                      for row in rows),
            "representative_causal_validation_complete": counts["UNKNOWN"] == 0
                                                        and counts["MISMATCH"] == 0,
            "runtime_capture_required_now": False,
        },
        "interpretation_limits": [
            "checkpoint labels describe user actions but are not original game semantic identifiers",
            "UNKNOWN preserves insufficient identity or causal evidence and is not a failed behavior",
            "a future runtime request must name the open core completion claim that the observation can close",
        ],
    }


def build(model_path: Path, windows_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    model = _load(model_path)
    windows = _load(windows_path)
    result = analyze(model, windows, _source(model_path), _source(windows_path))
    out.mkdir(parents=True)
    artifact_path = out / "controller-trace-conformance.json"
    artifact_path.write_bytes(canonical(result))
    report = {
        "schema": "uc.controller-trace-conformance-report.v1",
        "artifact": _source(artifact_path), "summary": result["summary"],
        "acceptance": result["acceptance"],
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.model.resolve(), args.windows.resolve(),
                     args.out.resolve())
    except Exception as error:
        write_failure(args.out, "controller_trace_conformance", error,
                      {key: str(value) for key, value in vars(args).items()})
        raise


if __name__ == "__main__":
    run_main(main)
