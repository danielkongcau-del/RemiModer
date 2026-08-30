"""End-to-end mark checkpoint and offline delta derivation on FixtureHost."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from checkpoint_delta import derive
from native_integration import Host


def main():
    root = ROOT / "test-output" / ("native-checkpoint-delta-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root / "host")
    try:
        host.control("apply", plan=host.make_plan(("mutate",), slots=32))
        first = host.control("mark", label="before-action")["checkpoint"]
        host.invoke("mutate", count=5)
        second = host.control("mark", label="after-action")["checkpoint"]
        stopped = host.stop()
        output = root / "checkpoint-deltas.json"
        derived = derive(Path(stopped["directory"]), output)
        document = json.loads(output.read_text(encoding="utf-8"))
        interval = document["intervals"][0]
        point = interval["points"][0]
        if [first["checkpoint_id"], second["checkpoint_id"]] != [1, 2]:
            raise AssertionError((first, second))
        if point["counter_delta"]["callbacks_observed"] != 5 or \
                point["counter_delta"]["records_captured"] != 10 or point["lost_events"]:
            raise AssertionError(point)
        if point["integrity"] != "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS":
            raise AssertionError(point)
        report = {"ok": True, "checkpoints": derived["checkpoints"],
                  "intervals": derived["intervals"], "callbacks": 5, "records_captured": 10,
                  "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
