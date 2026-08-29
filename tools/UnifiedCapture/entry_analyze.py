"""Classify every point in a sealed multi-entry capture without inferring behavior."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.caller import entry_return_address, resolve_callsite
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE
from uc.store import decode_chunk_file, inspect_session, read_manifest


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_new(path: Path, value: Any) -> None:
    with path.open("xb") as stream:
        stream.write(canonical(value))


def _load_finish(run: Path) -> dict[str, Any]:
    def order(path: Path):
        token = path.stem[len("finish-attempt-"):].split("-", 1)[0]
        return (int(token) if token.isdigit() else -1, path.name)
    attempts = sorted(run.glob("finish-attempt-*.json"), key=order)
    if attempts:
        return load(attempts[-1])
    final = run / "finish-result.json"
    if final.exists():
        return load(final)
    return {"clean": False, "state": "FINISH_RESULT_MISSING"}


def _annotate_observed_target(resolved, binding, bindings_by_point):
    """When a resolved call target is itself another observed point, say so.

    Direct calls into probed entries are common in game code; naming the
    observed point closes the caller→callee gap without inferring anything
    about indirect dispatch.
    """
    target_rva = (resolved.get("predecessor_instruction") or {}).get("direct_target_rva")
    base = binding.get("module_base")
    if target_rva is None or not isinstance(base, int):
        return
    target = base + target_rva
    for point_id, other in bindings_by_point.items():
        if other.get("address") == target:
            resolved["direct_target_is_observed_point"] = point_id
            return


def analyze_run(run: Path, out: Path, ledger_path: Path | None = None) -> dict[str, Any]:
    run, out = run.resolve(), out.resolve()
    intent, activation = load(run / "intent.json"), load(run / "activation-response.json")
    result = load(run / "result.json")
    finish = _load_finish(run)
    qualification = load(run / "site-qualification-evidence.json")
    derived_report = load(run / "derived/report.json")
    plan = load(Path(derived_report["entry_plan"]["path"]))
    session = Path(finish.get("directory") or activation["directory"]).resolve()
    inspection = inspect_session(session)
    manifest, manifest_errors = read_manifest(session / "session.manifest")
    session_header = next(row for row in manifest if row.get("kind") == "session")
    activation_rows = [row for row in manifest if row.get("kind") == "plan_activation"
                       and row.get("generation") == result["generation"]]
    marks = [row for row in manifest if row.get("kind") == "user_mark"]
    armed = [row["qpc"] for row in marks if row.get("label") == intent["armed_label"]]
    completed = [row["qpc"] for row in marks if row.get("label") == intent["finish_label"]]
    window = None
    if armed and completed:
        begin = max(armed);ends = [qpc for qpc in completed if qpc >= begin]
        if ends:
            window = [begin, min(ends)]
    all_events = []
    event_blobs: dict[int, bytes] = {}
    events_by_point: dict[str, list] = {}
    chunks = []
    for chunk in inspection["chunks"]:
        path = session / chunk["file"]
        chunks.append({"path": str(path), "sha256": file_hash(path)})
        _, rows = decode_chunk_file(path)
        for _, _, event, blob in rows:
            all_events.append(event)
            event_blobs[event["event_id"]] = blob
            events_by_point.setdefault(event.get("point"), []).append(event)
    generation = result["generation"]
    coverage = [row for row in manifest if row.get("kind") == "coverage" and row.get("generation") == generation]
    session_end = next((row for row in reversed(manifest) if row.get("kind") == "session_end"), {})
    loss_rows = session_end.get("loss", [])
    clean_store = inspection.get("storage_complete") is True and not manifest_errors \
        and inspection.get("cleanup") == "STOPPED_CLEAN" and finish.get("clean") is True
    qualified_process = qualification.get("response", {}).get("target_process", {})
    process_binding = plan.get("process_binding", {})
    bindings = [binding for row in activation_rows for binding in row.get("bindings", [])]
    bindings_by_point = {binding.get("point"): binding for binding in bindings}
    module_images: dict[str, NativePE] = {}
    for module_alias, module in plan.get("modules", {}).items():
        source = next((row for row in plan.get("sources", {}).values()
                       if row.get("sha256") == module.get("sha256")), None)
        if source is None:
            continue
        source_path = Path(source["path"])
        if source_path.is_file() and file_hash(source_path) == source.get("sha256"):
            module_images[module_alias] = NativePE(source_path)
    global_checks = {
        "process_binding_match": intent["pid"] == session_header.get("pid")
            == qualified_process.get("pid") == process_binding.get("pid"),
        "process_creation_match": qualified_process.get("creation_time_100ns")
            == process_binding.get("creation_time_100ns"),
        "session_identity_match": activation.get("session_id") == result.get("session_id")
            == finish.get("session_id") == session_header.get("session_id"),
        "plan_hash_match": activation.get("plan_hash") == result.get("plan_hash")
            and len(activation_rows) == 1 and activation_rows[0].get("plan_hash") == result.get("plan_hash"),
        "binding_set_complete": len(bindings) == len(plan["observations"])
            and {row.get("point") for row in bindings} == {row["id"] for row in plan["observations"]},
        "marked_action_window": window is not None,
        "storage_and_stop_clean": clean_store,
    }
    points = []
    for observation in plan["observations"]:
        point = observation["id"]
        events = [event for event in events_by_point.get(point, ())
                  if event.get("generation") == generation
                  and (window is None or window[0] <= event["qpc"] <= window[1])]
        covered = any(row.get("point") == point and row.get("complete") is True for row in coverage)
        losses = [row for row in loss_rows if row.get("point") == point and row.get("generation") == generation]
        lossless = len(losses) == 1 and all(losses[0].get(key) == 0 for key in
            ("events", "bytes", "unknown_byte_records", "read_failures", "truncated")) and all(
            value.get("occurrences") == 0 for value in losses[0].get("reasons", {}).values())
        raw = bool(events) and all(event.get("kind") == "probe"
            and event.get("raw_abi", {}).get("register_mask") == 131071
            and event.get("raw_abi", {}).get("xmm_mask") == 65535
            and event.get("read_failures") == 0 and event.get("truncated") == 0
            and any(read.get("id") == "raw-entry-stack-window" and read.get("status") == 1
                    and read.get("length") == 128 for read in event.get("reads", []))
            for event in events)
        if not clean_store or window is None or not covered or not lossless:
            status = "UNKNOWN"
        elif events and raw:
            status = "OBSERVED"
        elif events:
            status = "UNKNOWN_RAW_ABI_INCOMPLETE"
        else:
            status = "NOT_OBSERVED_IN_COVERED_WINDOW"
        caller_evidence = []
        binding = bindings_by_point.get(point)
        image = module_images.get(binding.get("module")) if binding else None
        if binding is not None and image is not None:
            for event in events:
                observed = entry_return_address(event, event_blobs[event["event_id"]])
                if observed is not None:
                    resolved = resolve_callsite(observed, binding, image)
                    resolved["event_id"] = event["event_id"]
                    _annotate_observed_target(resolved, binding, bindings_by_point)
                    caller_evidence.append(resolved)
        points.append({"point": point, "function_id": observation["native_exit_manifest"]["function_id"],
            "status": status, "event_count": len(events), "event_ids": [event["event_id"] for event in events],
            "coverage_complete": covered, "lossless": lossless, "raw_abi_complete": raw,
            "runtime_caller_evidence": caller_evidence,
            "resolved_runtime_callsite_count": sum(
                row.get("callsite_status") == "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"
                for row in caller_evidence),
        })
    accepted = all(global_checks.values()) and all(row["status"] in
        ("OBSERVED", "NOT_OBSERVED_IN_COVERED_WINDOW") for row in points)
    report = {"schema": "uc.entry-evidence-acceptance.v1", "accepted": accepted,
        "game_runtime_verified": accepted and bool(bindings)
            and all(binding.get("module") in ("game", "unity") for binding in bindings),
        "run": {"path": str(run), "intent_sha256": file_hash(run / "intent.json")},
        "session": {"path": str(session), "manifest_sha256": file_hash(session / "session.manifest"),
                    "chunks": chunks, "inspection": inspection},
        "unit_id": intent["unit_id"], "generation": generation, "action_window_qpc": window,
        "checks": global_checks,
        "points": points, "summary": {status: sum(row["status"] == status for row in points)
            for status in ("OBSERVED", "NOT_OBSERVED_IN_COVERED_WINDOW", "UNKNOWN", "UNKNOWN_RAW_ABI_INCOMPLETE")},
        "not_proven": ["behavior did not execute", "serialized instance identity", "owner/entity identity",
                       "semantic caller identity", "cross-thread causality", "complete controller"]}
    out.mkdir(parents=True, exist_ok=False)
    save_new(out / "entry-acceptance.json", report)
    if ledger_path is not None:
        ledger_path = ledger_path.resolve();ledger = load(ledger_path)
        known = {row["type"] for row in ledger["types"]}
        updates = []
        for row in points:
            type_name = row["function_id"].split(".", 1)[0]
            if row["status"] == "OBSERVED" and type_name in known:
                updates.append({"type": type_name, "axis": "dynamic_scheduling", "status": "PARTIAL",
                    "bounded_claim": "The native entry was observed inside this complete, lossless marked window.",
                    "point": row["point"], "does_not_promote": report["not_proven"]})
        overlay = {"schema": "uc.controller-closure-ledger-overlay.v1",
            "base": {"path": str(ledger_path), "sha256": file_hash(ledger_path)},
            "evidence": {"path": str((out / "entry-acceptance.json").resolve()),
                         "sha256": file_hash(out / "entry-acceptance.json")},
            "updates": updates, "complete_controller_acquired": False}
        save_new(out / "controller-ledger-overlay.json", overlay)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ledger", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_main(analyze_run, args.run, args.out, args.ledger), ensure_ascii=False))
