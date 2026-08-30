"""Prove one concurrently published key does not create a false busy gap."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host


def main():
    root = ROOT / "test-output" / ("native-retention-concurrency-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    report = {"ok": False}
    try:
        plan = host.make_plan(("gum",), slots=64)
        point = plan["points"][0]
        point["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 16}
        host.control("apply", plan=plan)
        result = host.invoke("stress_gum", count=10000, threads=8)
        status = host.control("status")
        retained = status["retention"][0]
        loss = status["loss"][0]
        if retained["callbacks"] != result["calls"] or retained["classified_callbacks"] != result["calls"]:
            raise AssertionError(retained)
        if len(retained["keys"]) != 1 or retained["retention_key_busy"] != 0 or not retained["complete_for_caller_counts"]:
            raise AssertionError(retained)
        if loss["reasons"]["retention_key_busy"]["events"] != 0:
            raise AssertionError(loss)
        host.stop()
        report = {"ok": True, "callbacks": result["calls"], "keys": 1,
                  "retention_key_busy": 0, "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
