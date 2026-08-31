"""End-to-end coverage for v2 read-program extensions: string, array, predicates.

Runs only on the owned fixture host. Exercises the new read operations and the
entry-phase predicate filter, including that filtered events are counted in the
sealed loss ledger instead of vanishing.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host
from uc.model import validate
from uc.store import inspect_session, read_manifest


def run():
    root = ROOT / "test-output" / ("native-read-program-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        target = host.info["targets"]["pair_entry"]
        # PairRuntimeTarget(uint64_t* slot, uint64_t add): rcx -> fixtureState.
        # fixtureState.value accumulates `add` per completed call (10 -> 13 -> 20),
        # so an entry-phase predicate on it demonstrably filters later calls.
        reads = [
            {"id": "value", "base": "rcx", "op": "scalar", "width": 8, "phase": "enter",
             "when": {"op": "eq", "value": 10}, "evidence": ["fixture"]},
            {"id": "count", "base": "rcx", "offset": 8, "op": "scalar", "width": 8,
             "phase": "enter", "evidence": ["fixture"]},
            {"id": "count-string", "base": "rcx", "offset": 8, "op": "string", "max_bytes": 16,
             "phase": "enter", "evidence": ["fixture"]},
            {"id": "window", "base": "rcx", "op": "array", "count_from": "count", "stride": 8,
             "max_count": 4, "phase": "enter", "evidence": ["fixture"]},
        ]
        register_reads = [
            {"id": "add-register", "base": "rdx", "op": "register", "width": 8,
             "phase": "enter", "when": {"op": "eq", "value": 3}, "evidence": ["fixture"]},
        ]
        register_in_reads = [
            {"id": "add-register-in", "base": "rdx", "op": "register", "width": 8,
             "phase": "enter", "when": {"op": "in", "values": [7]}, "evidence": ["fixture"]},
        ]
        plan = {"schema": "uc.capture-plan.v1", "plan_id": "read-program-fixture", "plan_revision": 1,
                "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
                "sources": {"fixture": {"path": host.info["module_path"], "sha256": host.info["sha256"]}},
                "resources": {"slots_per_point": 32, "max_record_bytes": 4096},
                "points": [{"id": "pair", "module": "fixture", "rva": target["rva"],
                            "expected_prefix": target["expected_prefix"], "evidence": ["fixture"],
                            "backend": "gum_probe", "reads": reads},
                           {"id": "pair-register-filter", "module": "fixture", "rva": target["rva"],
                            "expected_prefix": target["expected_prefix"], "evidence": ["fixture"],
                            "backend": "gum_probe", "reads": register_reads},
                           {"id": "pair-register-in-filter", "module": "fixture", "rva": target["rva"],
                            "expected_prefix": target["expected_prefix"], "evidence": ["fixture"],
                            "backend": "gum_probe", "reads": register_in_reads}]}
        validate(plan, verify_sources=True)
        host.control("apply", plan=plan)
        host.invoke("pair", add=3)   # entry value == 10: recorded
        host.invoke("pair", add=7)   # entry value == 13: filtered by plan
        host.invoke("pair", add=3)   # entry value == 20: filtered by plan
        # Hot-path regression: all three observations reject these calls in
        # the native early predicate gate, before pool/XMM/stack work.
        stress_begin = time.perf_counter()
        host.invoke("pair_stress", count=20_000)
        stress_seconds = time.perf_counter() - stress_begin
        assert stress_seconds < 5.0, stress_seconds
        running = host.control("status")
        timing = next(row for row in running["read_timing"] if row["point"] == "pair")
        assert timing["samples"] == 20_003 and timing["filtered_by_plan"] == 20_002, timing
        assert timing["early_predicate_enabled"] is False and timing["early_filtered_by_plan"] == 0, timing
        register_timing = next(row for row in running["read_timing"] if row["point"] == "pair-register-filter")
        assert register_timing["samples"] == 20_003 and register_timing["filtered_by_plan"] == 20_001, register_timing
        assert register_timing["early_predicate_enabled"] is True and register_timing["early_filtered_by_plan"] == 20_001, register_timing
        in_timing = next(row for row in running["read_timing"] if row["point"] == "pair-register-in-filter")
        assert in_timing["samples"] == 20_003 and in_timing["filtered_by_plan"] == 20_002, in_timing
        assert in_timing["early_predicate_enabled"] is True and in_timing["early_filtered_by_plan"] == 20_002, in_timing
        stopped = host.stop()
        from native_integration import records
        events = [event for event, _ in records(stopped["directory"])]
        assert len(events) == 4, [row["point"] for row in events]
        assert all(row["kind"] == "probe" and row["read_failures"] == 0 and row["truncated"] == 0
                   for row in events), events
        memory_event = next(row for row in events if row["point"] == "pair")
        register_events = [row for row in events if row["point"] == "pair-register-filter"]
        assert len(register_events) == 2, register_events
        in_events = [row for row in events if row["point"] == "pair-register-in-filter"]
        assert len(in_events) == 1 and in_events[0]["reads"][0]["value"] == 7, in_events
        by_id = {read["id"]: read for read in memory_event["reads"]}
        # scalar predicate carrier: entry-time value was still 10
        assert by_id["value"]["value"] == 10 and by_id["value"]["status"] == 1, by_id["value"]
        # fixtureState.count == 3: bytes 03 00 ... -> one byte before NUL
        assert by_id["count-string"]["status"] == 1, by_id["count-string"]
        assert by_id["count-string"]["value"] == 1 and by_id["count-string"]["length"] == 1, by_id["count-string"]
        # array: declared_count from the scalar, 3 elements of stride 8
        assert by_id["window"]["status"] == 1 and by_id["window"]["declared_count"] == 3, by_id["window"]
        assert by_id["window"]["length"] == 24, by_id["window"]
        for event in register_events:
            register_read = event["reads"][0]
            assert register_read["status"] == 1 and register_read["value"] == 3, register_read
            assert register_read["address"] == 0 and register_read["length"] == 8, register_read
        metadata, _ = read_manifest(Path(stopped["directory"]) / "session.manifest")
        session_end = next(row for row in reversed(metadata) if row.get("kind") == "session_end")
        filtered = [row for row in session_end["loss"] if row.get("filtered_by_plan")]
        assert sorted(row["filtered_by_plan"] for row in filtered) == [20_001, 20_002, 20_002], session_end["loss"]
        assert inspect_session(Path(stopped["directory"]))["storage_complete"]
        result = {"ok": True, "events": len(events), "filtered_by_plan": 60_005,
                  "timed_callback_samples": timing["samples"],
                  "stress_calls": 20_000, "stress_seconds": stress_seconds,
                  "stress_calls_per_second": 20_000 / stress_seconds,
                  "string_bytes": by_id["count-string"]["value"],
                  "array_bytes": by_id["window"]["length"],
                  "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **result}, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(run())
