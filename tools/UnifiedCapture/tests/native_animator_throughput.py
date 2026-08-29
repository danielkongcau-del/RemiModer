"""Stress the combined Animator retention/burst resource shape on our fixture."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from uc.probe_pair import compile_probe_pair
from uc.store import inspect_session


def main():
    root = ROOT / "test-output" / ("native-animator-throughput-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        names = tuple((f"animator-stage-{index:02d}", "pair") for index in range(13))
        plan = host.make_probe_pair_plan(names, slots=8192)
        plan["plan_id"] = "animator-throughput-shape-fixture-NOT-game-evidence"
        for index, observation in enumerate(plan["observations"]):
            observation["exit_capture_requirement"] = "none"
            observation["entry"]["reads"] = [{"id": "raw-entry-stack-window", "base": "rsp",
                "op": "block", "size": 128, "phase": "enter", "evidence": ["fixture"]}]
            if index in (0, 12):
                observation["retention"] = {
                    "mode": "first_per_entry_return_address", "max_keys": 1024}
        compile_probe_pair(plan)
        host.control("apply", plan=plan)
        host.invoke("pair_stress", count=4000)
        status = host.control("status")
        losses = [row for row in status["loss"] if row["generation"] == 1]
        if len(losses) != 13 or any(row["events"] for row in losses):
            raise AssertionError(losses)
        summaries = status["retention"]
        if len(summaries) != 2 or any(row["callbacks"] != 4000 or
                                      not row["complete_for_caller_counts"] for row in summaries):
            raise AssertionError(summaries)
        stopped = host.stop(timeout=30)
        events = [event for event, _ in records(stopped["directory"])]
        expected = 11 * 4000 + 2
        if len(events) != expected:
            raise AssertionError((len(events), expected))
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "callbacks_per_stage": 4000, "full_events": len(events),
                  "aggregate_stages": 2, "burst_buffer_stages": 11,
                  "preallocated_record_bytes": status["preallocated_record_bytes"],
                  "queue_loss_events": 0, "inspection": inspection,
                  "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "full_events", "preallocated_record_bytes", "queue_loss_events") if key in result}},
              ensure_ascii=False))


if __name__ == "__main__":
    main()
