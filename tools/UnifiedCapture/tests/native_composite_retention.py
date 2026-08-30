"""Verify collision-checked raw composite retention on the owned fixture."""
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
    root = ROOT / "test-output" / ("native-composite-retention-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        plan = host.make_probe_pair_plan((("composite", "pair"),), slots=8)
        observation = plan["observations"][0]
        observation["exit_capture_requirement"] = "none"
        observation["entry"]["reads"] = [row for row in observation["entry"]["reads"]
                                                if row.get("phase") != "leave"]
        observation["retention"] = {
            "mode": "first_per_composite_key", "max_keys": 8,
            "key": [
                {"kind": "entry_return_address", "evidence": ["fixture"]},
                {"kind": "register", "register": "rcx", "evidence": ["fixture"]},
            ],
        }
        compile_probe_pair(plan)
        host.control("apply", plan=plan)
        stressed = host.invoke("pair_composite_stress", count=20000)
        status = host.control("status")
        summary = status["retention"][0]
        if summary["callbacks"] != stressed["calls"] or summary["classified_callbacks"] != stressed["calls"]:
            raise AssertionError(summary)
        if summary["mode"] != "first_per_composite_key" or len(summary["keys"]) != 2:
            raise AssertionError(summary)
        if len({row["entry_return_address"] for row in summary["keys"]}) != 1:
            raise AssertionError(summary)
        receivers = {row["key_parts"][1]["value"] for row in summary["keys"]}
        if receivers != {host.info["object"], host.info["alternate_object"]}:
            raise AssertionError((receivers, host.info))
        if any(row["count"] != 10000 for row in summary["keys"]) or not summary["complete_for_caller_counts"]:
            raise AssertionError(summary)
        stopped = host.stop()
        events = [event for event, _ in records(stopped["directory"])]
        if len(events) != 2 or any(event.get("retention_key", {}).get("kind") != "composite" for event in events):
            raise AssertionError(events)
        if {event["retention_key"]["parts"][1]["value"] for event in events} != receivers:
            raise AssertionError(events)
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "callbacks": summary["callbacks"], "composite_keys": 2,
                  "full_events": len(events), "complete_for_caller_counts": True,
                  "inspection": inspection, "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "callbacks", "composite_keys", "full_events") if key in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
