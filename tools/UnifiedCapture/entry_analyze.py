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
from uc.store import decode_chunk_file, event_dictionary_context, inspect_session, read_manifest


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_new(path: Path, value: Any) -> None:
    with path.open("xb") as stream:
        stream.write(canonical(value))


def coverage_contains_window(rows: list[dict[str, Any]], point: str,
                             window: list[int] | None) -> bool:
    """Require one complete interval to contain the whole marked window.

    Merely having a complete coverage record for a point is insufficient: it
    may describe an earlier activation interval that does not overlap the
    user's marks at all.
    """
    if window is None:
        return False
    return any(
        row.get("point") == point and row.get("complete") is True
        and type(row.get("begin_qpc")) is int and type(row.get("end_qpc")) is int
        and row["begin_qpc"] <= window[0] and row["end_qpc"] >= window[1]
        for row in rows)


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


def _raw_probe_complete(event: dict[str, Any], observation: dict[str, Any]) -> bool:
    """Check the ABI/read evidence the immutable observation actually requested.

    A plan selecting GPR values must not be rejected merely because it did not
    request a stack window or XMM state.  Conversely, this never manufactures
    those absent evidence classes.
    """
    if event.get("kind") != "probe" or event.get("read_failures") != 0 \
            or event.get("truncated") != 0:
        return False
    raw_abi = event.get("raw_abi", {})
    if not isinstance(raw_abi.get("register_mask"), int):
        return False
    actual = {row.get("id"): row for row in event.get("reads", [])}
    for requested in observation.get("reads", []):
        if requested.get("phase", "enter") != "enter":
            continue
        row = actual.get(requested.get("id"))
        if row is None or row.get("status") != 1:
            return False
        expected = requested.get("width") if requested.get("op") in ("register", "scalar") \
            else requested.get("size") if requested.get("op") == "block" else None
        if expected is not None and row.get("length") != expected:
            return False
    return True


def _retained_return_address(event: dict[str, Any]) -> dict[str, Any] | None:
    key = event.get("retention_key", {})
    value = (key.get("value") if key.get("kind") == "entry_return_address"
             else key.get("entry_return_address") if key.get("kind") == "composite" else None)
    if not isinstance(value, int):
        return None
    return {"return_address": value,
            "source": "runtime-captured-architectural-entry-return-address",
            "retention_lane": key.get("lane"),
            "stack_slot_matches_rsp": "NOT_SEPARATELY_CAPTURED"}


def _retention_identity(row: dict[str, Any]) -> tuple | None:
    parts = row.get("key_parts") if "key_parts" in row else row.get("parts")
    if isinstance(parts, list) and parts:
        return tuple((part.get("kind"), part.get("register"), part.get("mask"), part.get("value"))
                     for part in parts)
    value = row.get("entry_return_address", row.get("value"))
    return ("entry_return_address", None, None, value) if isinstance(value, int) else None


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
    dictionary_context = event_dictionary_context(session / "session.manifest", manifest)
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
    observations_by_point = {row["id"]: row for row in plan["observations"]}
    point_states: dict[str, dict[str, Any]] = {}
    for point, observation in observations_by_point.items():
        point_states[point] = {
            "activation_count": 0, "window_count": 0, "event_ids": [],
            "raw_activation_seen": False, "raw_activation_complete": True,
            "raw_window_seen": False, "raw_window_complete": True,
            "caller_by_return": {}, "retention_sample_keys": set(), "retention_aggregate_seen": set(),
        }
    retention_by_point = {
        row.get("point"): row for row in retention_rows if row.get("generation") == generation
    }
    retention_keys_by_point = {
        point: {_retention_identity(row): row for row in summary.get("keys", [])}
        for point, summary in retention_by_point.items()
    }
    chunks = []
    for chunk in inspection["chunks"]:
        path = session / chunk["file"]
        chunks.append({"path": str(path), "sha256": file_hash(path)})
        _, rows = decode_chunk_file(path, dictionary_context=dictionary_context)
        for _, _, event, blob in rows:
            if event.get("generation") != generation:
                continue
            point = event.get("point")
            state = point_states.get(point)
            if state is None:
                continue
            state["activation_count"] += 1
            observation = observations_by_point[point]
            raw_ok = _raw_probe_complete(event, observation)
            state["raw_activation_seen"] = True
            state["raw_activation_complete"] &= raw_ok
            in_window = window is not None and window[0] <= event["qpc"] <= window[1]
            if in_window:
                state["window_count"] += 1
                if len(state["event_ids"]) < 64:
                    state["event_ids"].append(event["event_id"])
                state["raw_window_seen"] = True
                state["raw_window_complete"] &= raw_ok
            retention_policy = observation.get("retention")
            if retention_policy:
                retention_key = event.get("retention_key", {})
                identity = _retention_identity(retention_key)
                if identity is not None:
                    state["retention_sample_keys"].add(identity)
            if not (raw_ok and (retention_policy or in_window)):
                continue
            binding = bindings_by_point.get(point)
            image = module_images.get(binding.get("module")) if binding else None
            if binding is None or image is None:
                continue
            observed = _retained_return_address(event) if retention_policy else entry_return_address(event, blob)
            if observed is None:
                continue
            return_address = observed["return_address"]
            aggregate_identity = _retention_identity(event.get("retention_key", {})) if retention_policy else None
            aggregate = retention_keys_by_point.get(point, {}).get(aggregate_identity)
            prior = state["caller_by_return"].get(return_address)
            if prior is not None:
                if retention_policy and aggregate_identity not in state["retention_aggregate_seen"]:
                    prior["observation_count"] += int((aggregate or {}).get("count", 0))
                    prior["first_qpc"] = min(prior["first_qpc"], (aggregate or {}).get("first_qpc", event["qpc"]))
                    prior["last_qpc"] = max(prior["last_qpc"], (aggregate or {}).get("last_qpc", event["qpc"]))
                    state["retention_aggregate_seen"].add(aggregate_identity)
                elif not retention_policy:
                    prior["observation_count"] += 1
                    prior["first_qpc"] = min(prior["first_qpc"], event["qpc"])
                    prior["last_qpc"] = max(prior["last_qpc"], event["qpc"])
                continue
            resolved = resolve_callsite(observed, binding, image)
            resolved["module"] = binding.get("module")
            resolved["representative_event_id"] = event["event_id"]
            resolved["observation_count"] = aggregate["count"] if aggregate else 1
            resolved["first_qpc"] = aggregate["first_qpc"] if aggregate else event["qpc"]
            resolved["last_qpc"] = aggregate["last_qpc"] if aggregate else event["qpc"]
            _annotate_observed_target(resolved, binding, bindings_by_point)
            _annotate_observed_caller(resolved, binding, bindings_by_point)
            state["caller_by_return"][return_address] = resolved
            if aggregate_identity is not None:
                state["retention_aggregate_seen"].add(aggregate_identity)
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
        state = point_states[point]
        point_coverage = [row for row in coverage if row.get("point") == point]
        covered = coverage_contains_window(point_coverage, point, window)
        losses = [row for row in loss_rows if row.get("point") == point and row.get("generation") == generation]
        lossless = len(losses) == 1 and all(losses[0].get(key) == 0 for key in
            ("events", "bytes", "unknown_byte_records", "read_failures", "truncated")) and all(
            value.get("occurrences") == 0 for value in losses[0].get("reasons", {}).values())
        retention_policy = observation.get("retention")
        retention_generation = retention_by_point.get(point)
        required_keys = {_retention_identity(row) for row in (retention_generation or {}).get("keys", [])}
        raw = ((state["raw_activation_seen"] and state["raw_activation_complete"]
                and required_keys <= state["retention_sample_keys"])
               if retention_policy else
               (state["raw_window_seen"] and state["raw_window_complete"]))
        if not clean_store or window is None or not covered or not lossless or (retention_policy and
                (retention_generation is None or not retention_generation.get("complete_for_caller_counts"))):
            status = "UNKNOWN"
        elif retention_policy and retention_generation["callbacks"] and raw:
            status = "OBSERVED_AGGREGATED_CALLERS"
        elif retention_policy and retention_generation["callbacks"]:
            status = "UNKNOWN_RAW_ABI_INCOMPLETE"
        elif state["window_count"] and raw:
            status = "OBSERVED"
        elif state["window_count"]:
            status = "UNKNOWN_RAW_ABI_INCOMPLETE"
        else:
            status = "NOT_OBSERVED_IN_COVERED_WINDOW"
        caller_by_return = state["caller_by_return"]
        caller_evidence = [caller_by_return[key] for key in sorted(caller_by_return)]
        points.append({"point": point, "function_id": observation["native_exit_manifest"]["function_id"],
            "status": status, "event_count": state["window_count"],
            "event_ids": state["event_ids"], "event_ids_complete": state["window_count"] <= 64,
            "coverage_complete": covered,
            "coverage_contains_marked_window": covered,
            "coverage_intervals": [{"begin_qpc": row.get("begin_qpc"), "end_qpc": row.get("end_qpc"),
                                    "complete": row.get("complete")} for row in point_coverage],
            "lossless": lossless, "raw_abi_complete": raw,
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
    report = {"schema": "uc.entry-evidence-acceptance.v2", "accepted": accepted,
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
    value = run_main(analyze_run, args.run, args.out, args.ledger, args.unit)
    print(json.dumps({"schema": "uc.entry-evidence-acceptance-cli.v1",
                      "artifact": str((args.out.resolve() / "entry-acceptance.json")),
                      "accepted": value.get("accepted"),
                      "game_runtime_verified": value.get("game_runtime_verified"),
                      "generation": value.get("generation"),
                      "summary": value.get("summary", {}),
                      "runtime_execution_edges": len(value.get("runtime_execution_edges", []))},
                     ensure_ascii=False))
