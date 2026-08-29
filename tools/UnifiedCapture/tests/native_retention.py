"""Verify bounded return-address retention on our assembly fixture only."""
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
    root = ROOT / "test-output" / ("native-retention-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        plan = host.make_probe_pair_plan((("aggregate", "pair"),), slots=8)
        observation = plan["observations"][0]
        observation["exit_capture_requirement"] = "none"
        observation["entry"]["reads"] = [row for row in observation["entry"]["reads"]
                                                   if row.get("phase") != "leave"]
        observation["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 8}
        compile_probe_pair(plan)
        host.control("apply", plan=plan)
        host.invoke("pair", add=1)
        stressed = host.invoke("pair_stress", count=25000)
        status = host.control("status")
        summary = status["retention"][0]
        if summary["callbacks"] != stressed["calls"] + 1:
            raise AssertionError(summary)
        if summary["classified_callbacks"] != summary["callbacks"] or not summary["complete_for_caller_counts"]:
            raise AssertionError(summary)
        if sum(row["count"] for row in summary["keys"]) != summary["callbacks"]:
            raise AssertionError(summary)
        second_plan = json.loads(json.dumps(plan))
        second_plan["plan_revision"] = 18
        host.control("apply", plan=second_plan)
        host.invoke("pair_stress", count=10)
        host.control("apply", plan=plan)
        host.invoke("pair_stress", count=7)
        stopped = host.stop()
        events = [event for event, _ in records(stopped["directory"])]
        summaries = sorted(stopped["retention"], key=lambda row: row["generation"])
        if [row["callbacks"] for row in summaries] != [25001, 10, 7]:
            raise AssertionError(summaries)
        if len(events) != sum(len(row["keys"]) for row in summaries):
            raise AssertionError((events, summaries))
        if any(event.get("retention_key", {}).get("kind") != "entry_return_address" for event in events):
            raise AssertionError(events)
        final_summary = summaries[0]
        if final_summary != summary:
            raise AssertionError((summary, final_summary))
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "callbacks": summary["callbacks"], "caller_keys": len(summary["keys"]),
                  "full_events": len(events), "activation_generations": 3,
                  "suppressed_by_policy": sum(row["suppressed_by_policy"] for row in summaries),
                  "complete_for_caller_counts": True, "inspection": inspection,
                  "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "callbacks", "caller_keys", "full_events") if key in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
