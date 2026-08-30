"""A detached Hook object must not bypass current reservation overlap checks."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from capturectl import request
from native_integration import Host, records
from uc.model import validate


def main():
    root = ROOT / "test-output" / ("native-hook-overlap-reactivation-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    report = {"ok": False}
    try:
        original = host.make_plan(("gum",), revision=1, slots=64)
        host.control("apply", plan=original)
        host.invoke("gum", count=1)
        host.stop()

        shifted = copy.deepcopy(original)
        shifted["plan_id"] = "shifted-owned-hook"
        shifted["plan_revision"] = 2
        point = shifted["points"][0]
        # FixtureGum starts with a verified two-byte NOP followed by one-byte
        # NOPs. +2 is therefore an instruction boundary inside the old Hook's
        # 16-byte physical reservation.
        if not point["expected_prefix"].startswith("6690"):
            raise AssertionError(point["expected_prefix"])
        point["id"] = "gum-shifted"
        point["rva"] += 2
        point["expected_prefix"] = point["expected_prefix"][4:]
        validate(shifted, verify_sources=True)
        host.control("apply", plan=shifted)

        resurrect = copy.deepcopy(original)
        resurrect["plan_revision"] = 3
        failed = request(host.info["pid"], "apply", plan=resurrect)
        if failed.get("ok") is not False or "partial physical hook reservation overlap" not in failed.get("error", ""):
            raise AssertionError(failed)
        host.invoke("gum", count=3)
        stopped = host.stop()
        shifted_events = [row for row, _ in records(stopped["directory"]) if row["point"] == "gum-shifted"]
        if len(shifted_events) != 3:
            raise AssertionError(shifted_events)
        report = {"ok": True, "reused_detached_hook_rejected_before_install": True,
                  "active_overlapping_hook_preserved": True, "events_after_rejection": len(shifted_events),
                  "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
