"""Verify one physical Gum probe fans out to exact logical subscriptions."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from uc.model import validate
from uc.store import inspect_session


def main():
    root = ROOT / "test-output" / ("native-probe-sharing-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        target = host.info["targets"]["gum"]
        plan = {"schema": "uc.capture-plan.v1", "plan_id": "physical-sharing-fixture",
                "plan_revision": 1,
                "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
                "sources": {"fixture": {"path": host.info["module_path"], "sha256": host.info["sha256"]}},
                "resources": {"slots_per_point": 16, "max_record_bytes": 256}, "points": []}
        for name in ("logical-a", "logical-b"):
            plan["points"].append({"id": name, "module": "fixture", "rva": target["rva"],
                "backend": "gum_probe", "expected_prefix": target["expected_prefix"],
                "evidence": ["fixture"], "reads": [{"id": "receiver", "base": "rcx", "op": "scalar",
                    "width": 8, "phase": "enter", "evidence": ["fixture"]}]})
        validate(plan, verify_sources=True)
        applied = host.control("apply", plan=plan)
        running = host.control("status")
        if len(running["hooks"]) != 1:
            raise AssertionError(running["hooks"])
        host.invoke("gum")
        stopped = host.stop()
        rows = records(stopped["directory"])
        points = [event["point"] for event, _ in rows]
        if points.count("logical-a") != 1 or points.count("logical-b") != 1:
            raise AssertionError(points)
        if any(event["kind"] != "probe" for event, _ in rows):
            raise AssertionError(rows)
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "generation": applied["generation"], "physical_hooks": 1,
                  "logical_events": len(rows), "points": points, "inspection": inspection,
                  "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{k: result[k] for k in
              ("ok", "physical_hooks", "logical_events") if k in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
