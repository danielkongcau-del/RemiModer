"""End-to-end native v2 probe-pair test on explicit assembly fixtures only."""
from __future__ import annotations

import copy
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
    root = ROOT / "test-output" / ("native-probe-pair-v2-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        plan = host.make_probe_pair_plan((
            ("pair-a", "pair"), ("pair-b", "pair"),
            ("recursive", "pair_recursive"), ("block", "pair_block")))
        # Eight bytes at entry plus eight bytes at leave must fit an eight-byte
        # per-event budget; summing mutually exclusive phases would reject it.
        plan["resources"]["max_record_bytes"] = 8
        invalid = copy.deepcopy(plan)
        invalid["observations"][0]["entry"]["reads"][1]["base"] = "receiver"
        try:
            host.control("apply", request_id="reject-cross-phase-read", plan=invalid)
        except RuntimeError as error:
            if "dependency unavailable at selected phase" not in str(error):
                raise
        else:
            raise AssertionError("native compiler accepted a cross-phase read dependency")
        if host.control("status")["generation"] != 0:
            raise AssertionError("failed v2 preparation published a generation")
        compiled = compile_probe_pair(plan)
        if len(compiled.sites) != 6:
            raise AssertionError(compiled.sites)
        first = host.control("apply", plan=plan)
        host.invoke("pair_block")
        pending = host.control("status")
        if pending["in_flight"] != 1:
            raise AssertionError(pending)
        second_plan = copy.deepcopy(plan)
        second_plan["plan_revision"] = 18
        second = host.control("apply", plan=second_plan)
        pair_result = host.invoke("pair", add=3)["value"]
        host.invoke("pair_recursive", depth=3)
        host.invoke("release")
        stopped = host.stop()
        rows = [event for event, _ in records(stopped["directory"])]
        by_point = {name: [row for row in rows if row["point"] == name]
                    for name in ("pair-a", "pair-b", "recursive", "block")}
        if any([row["kind"] for row in by_point[name]] != ["enter", "leave"] for name in ("pair-a", "pair-b")):
            raise AssertionError(by_point)
        for name in ("pair-a", "pair-b"):
            enter_reads = {row["id"]: row for row in by_point[name][0]["reads"]}
            leave_reads = {row["id"]: row for row in by_point[name][1]["reads"]}
            if enter_reads["receiver"]["status"] != 1 or enter_reads["receiver-after"]["status"] != 0:
                raise AssertionError(enter_reads)
            if leave_reads["receiver"]["status"] != 0 or leave_reads["receiver-after"]["status"] != 1:
                raise AssertionError(leave_reads)
            if leave_reads["receiver-after"]["value"] != pair_result:
                raise AssertionError((leave_reads, pair_result))
        if len(by_point["recursive"]) != 8 or sum(row["kind"] == "leave" for row in by_point["recursive"]) != 4:
            raise AssertionError(by_point["recursive"])
        if {row["generation"] for row in by_point["block"]} != {first["generation"]}:
            raise AssertionError(by_point["block"])
        if [row["kind"] for row in by_point["block"]] != ["enter", "leave"]:
            raise AssertionError(by_point["block"])
        leaves = [row for row in rows if row["kind"] == "leave"]
        if not leaves or any("normal_exit" not in row for row in leaves):
            raise AssertionError(leaves)
        if any(row["kind"] == "frame_absent_after_observed_point" for row in rows):
            raise AssertionError(rows)
        inspection = inspect_session(stopped["directory"])
        if not inspection["storage_complete"]:
            raise AssertionError(inspection)
        result = {"ok": True, "generations": [first["generation"], second["generation"]],
                  "events": len(rows), "normal_leaves": len(leaves), "recursive_calls": 4,
                  "shared_entry_logical_observations": 2, "old_generation_leave_preserved": True,
                  "leave_phase_read_program_verified": True,
                  "native_cross_phase_dependency_rejected": True,
                  "per_phase_record_budget_verified": True,
                  "inspection": inspection, "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "events", "normal_leaves") if key in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
