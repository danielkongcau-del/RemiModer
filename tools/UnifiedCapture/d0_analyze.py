"""Validate a sealed D0 run and produce a source-bound controller ledger overlay."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.caller import entry_return_address, resolve_callsite
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE
from uc.store import decode_chunk_file, inspect_session, read_manifest


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_finish(run: Path) -> dict[str, Any]:
    def order(path: Path):
        token = path.stem[len("finish-attempt-"):].split("-", 1)[0]
        return (int(token) if token.isdigit() else -1, path.name)
    attempts = sorted(run.glob("finish-attempt-*.json"), key=order)
    if attempts:
        # Attempt sequence is allocated by exclusive file creation. It is the
        # protocol order and is immune to copied mtimes or wall-clock rollback.
        return _load(attempts[-1])
    final = run / "finish-result.json"
    if final.exists():
        return _load(final)
    return {"clean": False, "state": "FINISH_RESULT_MISSING"}


def _save_new(path: Path, value: Any) -> None:
    with path.open("xb") as stream:
        stream.write(canonical(value))


def analyze_run(run: Path, out: Path, ledger_path: Path | None = None) -> dict[str, Any]:
    run, out = run.resolve(), out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    intent = _load(run / "intent.json")
    activation = _load(run / "activation-response.json")
    orchestration = _load(run / "result.json")
    finish = _load_finish(run)
    qualification = _load(run / "site-qualification-evidence.json")
    derived_report = _load(run / "derived/report.json")
    derived_plan = _load(Path(derived_report["entry_plan"]["path"]))
    session = Path(finish.get("directory") or activation["directory"]).resolve()
    inspection = inspect_session(session)
    manifest_records, manifest_errors = read_manifest(session / "session.manifest")
    session_header = next(row for row in manifest_records if row.get("kind") == "session")
    session_end = next((row for row in reversed(manifest_records) if row.get("kind") == "session_end"), None)
    activations = [row for row in manifest_records if row.get("kind") == "plan_activation"]
    coverages = [row for row in manifest_records if row.get("kind") == "coverage"]
    marks = [row for row in manifest_records if row.get("kind") == "user_mark"]
    point = intent["function_id"] + "/d0-entry"
    generation = orchestration["generation"]
    events = []
    event_blobs: dict[int, bytes] = {}
    chunk_sources = []
    for chunk in inspection["chunks"]:
        chunk_path = session / chunk["file"]
        chunk_sources.append({"path": str(chunk_path), "sha256": file_hash(chunk_path)})
        _, records = decode_chunk_file(chunk_path)
        for _, _, event, blob in records:
            if event.get("point") == point and event.get("generation") == generation:
                events.append(event)
                event_blobs[event["event_id"]] = blob
    point_loss = [] if session_end is None else [
        row for row in session_end.get("loss", [])
        if row.get("point") == point and row.get("generation") == generation
    ]
    lossless = len(point_loss) == 1 and all(
        point_loss[0].get(key) == 0
        for key in ("events", "bytes", "unknown_byte_records", "read_failures", "truncated")
    ) and all(
        value.get("occurrences") == 0
        for value in point_loss[0].get("reasons", {}).values()
    )
    complete_coverage = any(
        row.get("point") == point and row.get("generation") == generation and row.get("complete") is True
        for row in coverages
    )
    labels = [row.get("label") for row in marks]
    armed_qpcs = [row["qpc"] for row in marks if row.get("label") == "D0_ARMED"]
    complete_qpcs = [row["qpc"] for row in marks if row.get("label") == "D0_ACTION_COMPLETE"]
    action_window = None
    if armed_qpcs and complete_qpcs:
        begin = max(armed_qpcs)
        ends = [value for value in complete_qpcs if value >= begin]
        if ends:
            action_window = [begin, min(ends)]
    window_events = events if action_window is None else [
        event for event in events if action_window[0] <= event["qpc"] <= action_window[1]
    ]
    raw_abi_complete = bool(window_events) and all(
        event.get("kind") == "probe"
        and event.get("raw_abi", {}).get("register_mask") == (1 << 17) - 1
        and event.get("raw_abi", {}).get("xmm_mask") == (1 << 16) - 1
        and event.get("semantic_interpretation", {}).get("version") == "uc.raw-only.v1"
        and event.get("read_failures") == 0
        and event.get("truncated") == 0
        and any(
            read.get("id") == "raw-entry-stack-window"
            and read.get("status") == 1 and read.get("length") == 128
            for read in event.get("reads", [])
        )
        for event in window_events
    )
    game_binding_row = next((
        binding for row in activations if row.get("generation") == generation
        for binding in row.get("bindings", [])
        if binding.get("module") == "game" and binding.get("function_id") == intent["function_id"]
    ), None)
    # Fixture tests use a different module alias. The process-bound function
    # identity is still exact and lets the same parser validate itself.
    active_binding = game_binding_row or next((
        binding for row in activations if row.get("generation") == generation
        for binding in row.get("bindings", []) if binding.get("function_id") == intent["function_id"]
    ), None)
    caller_evidence = []
    if active_binding is not None:
        source = derived_plan.get("sources", {}).get("game-module")
        if source is None:
            source = next(iter(derived_plan.get("sources", {}).values()), None)
        if source and Path(source["path"]).is_file() and file_hash(Path(source["path"])) == source.get("sha256"):
            native_image = NativePE(Path(source["path"]))
            observed_points = {binding.get("address"): binding.get("point")
                               for row in activations for binding in row.get("bindings", [])}
            for event in window_events:
                observed = entry_return_address(event, event_blobs[event["event_id"]])
                if observed is not None:
                    resolved = resolve_callsite(observed, active_binding, native_image)
                    resolved["event_id"] = event["event_id"]
                    target_rva = (resolved.get("predecessor_instruction") or {}).get("direct_target_rva")
                    base = active_binding.get("module_base")
                    if target_rva is not None and isinstance(base, int) and base + target_rva in observed_points:
                        resolved["direct_target_is_observed_point"] = observed_points[base + target_rva]
                    caller_evidence.append(resolved)
    qualified_process = qualification.get("response", {}).get("target_process", {})
    process_binding = derived_plan.get("process_binding", {})
    checks = {
        "qualification_process_binding_match": (
            intent["pid"] == qualified_process.get("pid") == process_binding.get("pid")
            and qualified_process.get("creation_time_100ns") == process_binding.get("creation_time_100ns")
        ),
        "session_pid_match": intent["pid"] == session_header.get("pid"),
        "session_id_match": activation.get("session_id") == session_header.get("session_id") == finish.get("session_id"),
        "plan_hash_match": orchestration.get("plan_hash") == activation.get("plan_hash") and any(
            row.get("generation") == generation and row.get("plan_hash") == orchestration.get("plan_hash")
            for row in activations
        ),
        "storage_complete": inspection.get("storage_complete") is True and not manifest_errors,
        "stopped_clean": inspection.get("cleanup") == "STOPPED_CLEAN" and finish.get("clean") is True,
        "coverage_complete": complete_coverage,
        "lossless_for_point_generation": lossless,
        "entry_observed_in_action_window": bool(window_events),
        "raw_abi_and_stack_complete": raw_abi_complete,
        "armed_mark_present": "D0_ARMED" in labels,
        "action_complete_mark_present": "D0_ACTION_COMPLETE" in labels,
    }
    accepted = all(checks.values())
    game_binding = game_binding_row is not None
    resolved_callsites = [row for row in caller_evidence
                          if row.get("callsite_status") == "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"]
    report = {
        "schema": "uc.d0-evidence-acceptance.v1",
        "accepted": accepted,
        "game_runtime_verified": accepted and game_binding,
        "run": {"path": str(run), "intent_sha256": file_hash(run / "intent.json")},
        "session": {"path": str(session), "manifest_sha256": file_hash(session / "session.manifest"),
                    "chunks": chunk_sources, "inspection": inspection},
        "function_id": intent["function_id"], "point": point, "generation": generation,
        "event_count_total": len(events),
        "event_count_in_action_window": len(window_events),
        "event_ids_in_action_window": [event["event_id"] for event in window_events],
        "runtime_caller_evidence": caller_evidence,
        "resolved_runtime_callsite_count": len(resolved_callsites),
        "action_window_qpc": action_window,
        "qpc_range": [min((event["qpc"] for event in window_events), default=None),
                      max((event["qpc"] for event in window_events), default=None)],
        "checks": checks,
        "bounded_conclusion": (
            "The selected native entry was observed in a complete, lossless D0 coverage window with raw ABI evidence; entry-stack return addresses are reported separately as mechanically resolved callsites when possible."
            if accepted else "D0 evidence is not accepted; no runtime controller claim is promoted."
        ),
        "not_proven": ["serialized instance identity", "owner/entity identity", "semantic caller identity",
                       "function completion", "cross-thread causality", "complete controller"],
    }
    _save_new(out / "d0-acceptance.json", report)
    if ledger_path is not None:
        ledger_path = ledger_path.resolve()
        ledger = _load(ledger_path)
        type_name = intent["function_id"].split(".", 1)[0]
        if not any(row.get("type") == type_name for row in ledger.get("types", [])):
            raise ValueError(f"{type_name} is absent from controller ledger")
        overlay = {
            "schema": "uc.controller-closure-ledger-overlay.v1",
            "base": {"path": str(ledger_path), "sha256": file_hash(ledger_path)},
            "evidence": {"path": str((out / "d0-acceptance.json").resolve()),
                         "sha256": file_hash(out / "d0-acceptance.json")},
            "updates": [] if not accepted else [{
                "type": type_name,
                "axis": "dynamic_scheduling",
                "status": "PARTIAL",
                "bounded_claim": report["bounded_conclusion"],
                "does_not_promote": report["not_proven"],
            }],
            "complete_controller_acquired": False,
        }
        _save_new(out / "controller-ledger-overlay.json", overlay)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_main(analyze_run, args.run, args.out, args.ledger), ensure_ascii=False))
