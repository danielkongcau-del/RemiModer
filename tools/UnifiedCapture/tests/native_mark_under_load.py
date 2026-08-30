"""Keep the ready consumer live while repeated durable marks are requested."""
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


def main():
    root = ROOT / "test-output" / ("native-mark-under-load-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    report = {"ok": False}
    try:
        plan = host.make_plan(("gum",), slots=8192)
        host.control("apply", plan=plan)
        host.invoke("start_gum_stress", threads=2)
        time.sleep(.05)
        marks = [host.control("mark", label=f"LOAD_{index}")["checkpoint"] for index in range(20)]
        produced = host.invoke("stop_gum_stress")["calls"]
        status = host.control("status")
        point_loss = status["loss"][0]
        if point_loss["reasons"]["record_pool_exhausted"]["events"] or \
                point_loss["reasons"]["store_backpressure"]["events"]:
            raise AssertionError(point_loss)
        if [row["checkpoint_id"] for row in marks] != list(range(1, 21)):
            raise AssertionError(marks)
        if any(row["snapshot_end_qpc"] < row["snapshot_begin_qpc"] for row in marks):
            raise AssertionError(marks)
        stopped = host.stop(timeout=30)
        report = {"ok": True, "produced": produced, "marks": len(marks),
                  "ready_queue_high_water": stopped["point_metrics"][0]["ready_queue_high_water"],
                  "record_pool_exhausted": 0, "store_backpressure": 0,
                  "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
