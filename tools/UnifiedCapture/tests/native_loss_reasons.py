"""Verify capacity-loss attribution on owned recursive assembly fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host


def run_case(root: Path, resource: str):
    host = Host(root)
    try:
        plan = host.make_probe_pair_plan(("pair_recursive",), slots=16)
        plan["resources"]["thread_nesting_limit"] = 1 if resource == "thread_nesting_capacity" else 16
        plan["resources"]["call_frames_per_function"] = 1 if resource == "pair_frame_capacity" else 16
        host.control("apply", plan=plan)
        host.invoke("pair_recursive", depth=3)
        status = host.stop()
        loss = status["loss"][0]
        if loss["reasons"][resource]["events"] != 6 or loss["events"] != 6:
            raise AssertionError(loss)
        other = "pair_frame_capacity" if resource == "thread_nesting_capacity" else "thread_nesting_capacity"
        if loss["reasons"][other]["events"]:
            raise AssertionError(loss)
        if loss.get("exact_stream_state") != "BROKEN_WITH_GAPS" or \
                not isinstance(loss.get("exact_coverage_end_qpc"), int) or \
                loss["exact_coverage_end_qpc"] < loss["exact_coverage_begin_qpc"]:
            raise AssertionError(loss)
        metrics = status["point_metrics"][0]
        if metrics["callbacks_observed"] != 4 or metrics["records_encoded"] != 2:
            raise AssertionError(metrics)
        return {"lost_events": loss["events"], "callbacks": metrics["callbacks_observed"]}
    finally:
        host.close()


def main():
    root = ROOT / "test-output" / ("native-loss-reasons-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    result = {name: run_case(root / name, name) for name in
              ("thread_nesting_capacity", "pair_frame_capacity")}
    report = {"ok": True, "results": result, "game_runtime_verified": False}
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
