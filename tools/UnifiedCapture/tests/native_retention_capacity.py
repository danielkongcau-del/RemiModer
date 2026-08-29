"""Prove aggregation-table exhaustion becomes durable loss, never silence."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host
from uc.store import inspect_session


def main():
    root = ROOT / "test-output" / ("native-retention-capacity-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        plan = host.make_probe_pair_plan((("aggregate", "pair"),), slots=8)
        observation = plan["observations"][0]
        observation["exit_capture_requirement"] = "none"
        observation["entry"]["reads"] = [row for row in observation["entry"]["reads"]
                                                   if row.get("phase") != "leave"]
        observation["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 1}
        host.control("apply", plan=plan)
        # These commands call the same native entry from two distinct source
        # callsites. A one-key table must reject and account the second key.
        host.invoke("pair", add=1)
        host.invoke("pair_stress", count=5)
        stopped = host.stop()
        summary = stopped["retention"][0]
        loss = next(row for row in stopped["loss"] if row["point"] == "aggregate")
        capacity = loss["reasons"]["retention_capacity"]
        if summary["complete_for_caller_counts"] or capacity["events"] != 5 or loss["events"] != 5:
            raise AssertionError((summary, loss))
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "retention_capacity_loss": capacity["events"],
                  "silent_loss": False, "inspection": inspection, "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "retention_capacity_loss", "silent_loss") if key in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
