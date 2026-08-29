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


def _annotate_observed_caller(resolved, binding, bindings_by_point):
    """Bind a PDATA-owned caller range to observed function entries."""
    runtime_function = resolved.get("caller_runtime_function") or {}
    begin, end = runtime_function.get("begin_rva"), runtime_function.get("end_rva")
    base = binding.get("module_base")
    if not all(isinstance(value, int) for value in (begin, end, base)):
        return
    owners = []
    for point_id, other in bindings_by_point.items():
        if other.get("module") != binding.get("module") or not isinstance(other.get("address"), int):
            continue
        rva = other["address"] - base
        if begin <= rva < end:
            owners.append({"point": point_id, "rva": rva,
                           "relation": "entry_matches_runtime_function_begin" if rva == begin
                                       else "entry_inside_runtime_function"})
    if owners:
        resolved["caller_runtime_function_observed_points"] = owners


def _campaign_unit(run: Path, unit_id: str | None) -> Path:
    units = run / "units"
    if not units.is_dir():
        if unit_id is not None:
            raise ValueError("--unit is only valid for a campaign run")
        return run
    candidates = sorted(path for path in units.iterdir() if path.is_dir())
    if unit_id is None:
        if len(candidates) != 1:
            raise ValueError("campaign has multiple units; select one with --unit")
        return candidates[0]
    selected = units / unit_id
    if selected not in candidates:
        raise ValueError(f"unknown campaign unit: {unit_id}")
    return selected


def analyze_run(run: Path, out: Path, ledger_path: Path | None = None,
                unit_id: str | None = None) -> dict[str, Any]:
    run, out = run.resolve(), out.resolve()
    unit_run = _campaign_unit(run, unit_id)
    intent, activation = load(unit_run / "intent.json"), load(unit_run / "activation-response.json")
    result = load(unit_run / "result.json")
    finish = _load_finish(run)
    qualification = load(run / "site-qualification-evidence.json")
    derived_report = load(unit_run / "derived/report.json")
    plan = load(Path(derived_report["entry_plan"]["path"]))
    session = Path(finish.get("directory") or activation["directory"]).resolve()
    inspection = inspect_session(session)
    manifest, manifest_errors = read_manifest(session / "session.manifest")
    session_header = next(row for row in manifest if row.get("kind") == "session")
    activation_rows = [row for row in manifest if row.get("kind") == "plan_activation"
                       and row.get("generation") == result["generation"]]
    marks = [row for row in manifest if row.get("kind") == "user_mark"]
    armed = [row["qpc"] for row in marks if row.get("label") == intent["armed_label"]]
    complete_label = intent.get("finish_label") or intent.get("complete_label")
    if not complete_label:
        raise ValueError("run intent has no completion label")
    completed = [row["qpc"] for row in marks if row.get("label") == complete_label]
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
    retention_rows = [row.get("retention") for row in manifest
                      if row.get("kind") in ("retention_summary", "generation_point_retired")
                      and isinstance(row.get("retention"), dict)]
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
        retention_policy = observation.get("retention")
        all_point_events = [event for event in events_by_point.get(point, ())
                            if event.get("generation") == generation]
        raw_events = all_point_events if retention_policy else events
        retention_generation = next((row for row in reversed(retention_rows)
                                     if row.get("point") == point and row.get("generation") == generation), None)
        sample_keys = {event.get("retention_key", {}).get("value") for event in raw_events
                       if event.get("retention_key", {}).get("kind") == "entry_return_address"}
        required_keys = {row.get("entry_return_address") for row in (retention_generation or {}).get("keys", [])}
        raw = bool(raw_events) and all(event.get("kind") == "probe"
            and event.get("raw_abi", {}).get("register_mask") == 131071
            and event.get("raw_abi", {}).get("xmm_mask") == 65535
            and event.get("read_failures") == 0 and event.get("truncated") == 0
            and any(read.get("id") == "raw-entry-stack-window" and read.get("status") == 1
                    and read.get("length") == 128 for read in event.get("reads", []))
            for event in raw_events) and (not retention_policy or required_keys <= sample_keys)
        if not clean_store or window is None or not covered or not lossless or (retention_policy and
                (retention_generation is None or not retention_generation.get("complete_for_caller_counts"))):
            status = "UNKNOWN"
        elif retention_policy and retention_generation["callbacks"] and raw:
            status = "OBSERVED_AGGREGATED_CALLERS"
        elif retention_policy and retention_generation["callbacks"]:
            status = "UNKNOWN_RAW_ABI_INCOMPLETE"
        elif events and raw:
            status = "OBSERVED"
        elif events:
            status = "UNKNOWN_RAW_ABI_INCOMPLETE"
        else:
            status = "NOT_OBSERVED_IN_COVERED_WINDOW"
        retention_by_return = {row["entry_return_address"]: row
                               for row in (retention_generation or {}).get("keys", [])}
        caller_by_return: dict[int, dict[str, Any]] = {}
        binding = bindings_by_point.get(point)
        image = module_images.get(binding.get("module")) if binding else None
        if binding is not None and image is not None:
            for event in raw_events:
                observed = entry_return_address(event, event_blobs[event["event_id"]])
                if observed is not None:
                    return_address = observed["return_address"]
                    prior = caller_by_return.get(return_address)
                    if prior is not None:
                        if retention_policy:
                            continue
                        prior["observation_count"] += 1
                        prior["first_qpc"] = min(prior["first_qpc"], event["qpc"])
                        prior["last_qpc"] = max(prior["last_qpc"], event["qpc"])
                        continue
                    resolved = resolve_callsite(observed, binding, image)
                    resolved["representative_event_id"] = event["event_id"]
                    aggregate = retention_by_return.get(return_address)
                    resolved["observation_count"] = aggregate["count"] if aggregate else 1
                    resolved["first_qpc"] = aggregate["first_qpc"] if aggregate else event["qpc"]
                    resolved["last_qpc"] = aggregate["last_qpc"] if aggregate else event["qpc"]
                    _annotate_observed_target(resolved, binding, bindings_by_point)
                    _annotate_observed_caller(resolved, binding, bindings_by_point)
                    caller_by_return[return_address] = resolved
        caller_evidence = [caller_by_return[key] for key in sorted(caller_by_return)]
        points.append({"point": point, "function_id": observation["native_exit_manifest"]["function_id"],
            "status": status, "event_count": len(events), "event_ids": [event["event_id"] for event in events],
            "coverage_complete": covered, "lossless": lossless, "raw_abi_complete": raw,
            "evidence_scope": "activation_generation" if retention_policy else "marked_window",
            "retention_generation": ({**retention_generation, "scope": "activation_generation",
                "temporal_event_trace_complete": False} if retention_generation is not None else None),
            "runtime_caller_evidence": caller_evidence,
            "runtime_call_observation_count": sum(row["observation_count"] for row in caller_evidence),
            "resolved_runtime_callsite_count": sum(
                row["observation_count"] for row in caller_evidence
                if row.get("callsite_status") == "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"),
            "unique_resolved_runtime_callsite_count": sum(
                row.get("callsite_status") == "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"
                for row in caller_evidence),
        })
    execution_edges: dict[tuple[str, str], dict[str, Any]] = {}
    for point in points:
        for caller in point["runtime_caller_evidence"]:
            for owner in caller.get("caller_runtime_function_observed_points", []):
                if owner["relation"] != "entry_matches_runtime_function_begin":
                    continue
                key = owner["point"], point["point"]
                edge = execution_edges.setdefault(key, {"caller_point": key[0], "callee_point": key[1],
                    "observation_count": 0, "callsite_rvas": [],
                    "evidence_scope": point["evidence_scope"],
                    "evidence": "runtime return address + unique predecessor call + PDATA caller ownership"})
                edge["observation_count"] += caller["observation_count"]
                edge["callsite_rvas"].append(caller["callsite_rva"])
    for edge in execution_edges.values():
        edge["callsite_rvas"] = sorted(set(edge["callsite_rvas"]))
    accepted = all(global_checks.values()) and all(row["status"] in
        ("OBSERVED", "OBSERVED_AGGREGATED_CALLERS", "NOT_OBSERVED_IN_COVERED_WINDOW") for row in points)
    report = {"schema": "uc.entry-evidence-acceptance.v1", "accepted": accepted,
        "game_runtime_verified": accepted and bool(bindings)
            and all(binding.get("module") in ("game", "unity") for binding in bindings),
        "run": {"path": str(run), "unit_path": str(unit_run),
                "intent_sha256": file_hash(unit_run / "intent.json")},
        "session": {"path": str(session), "manifest_sha256": file_hash(session / "session.manifest"),
                    "chunks": chunks, "inspection": inspection},
        "unit_id": intent["unit_id"], "generation": generation, "action_window_qpc": window,
        "checks": global_checks,
        "points": points, "runtime_execution_edges": [execution_edges[key] for key in sorted(execution_edges)],
        "summary": {status: sum(row["status"] == status for row in points)
            for status in ("OBSERVED", "OBSERVED_AGGREGATED_CALLERS", "NOT_OBSERVED_IN_COVERED_WINDOW", "UNKNOWN", "UNKNOWN_RAW_ABI_INCOMPLETE")},
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
            if row["status"] in ("OBSERVED", "OBSERVED_AGGREGATED_CALLERS") and type_name in known:
                bounded_claim = ("The native entry had one or more callers during this complete, lossless activation generation; "
                    "the aggregate does not prove marked-window timing." if row["status"] == "OBSERVED_AGGREGATED_CALLERS" else
                    "The native entry was observed inside this complete, lossless marked window.")
                updates.append({"type": type_name, "axis": "dynamic_scheduling", "status": "PARTIAL",
                    "bounded_claim": bounded_claim,
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
    parser.add_argument("--unit")
    args = parser.parse_args()
    print(json.dumps(run_main(analyze_run, args.run, args.out, args.ledger, args.unit), ensure_ascii=False))
