"""Verify aggregate-before-pair gating on owned entry/exit assembly fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from exact_caller_promotion_plan import derive
from uc.model import canonical
from uc.store import read_manifest


def plan_for(host: Host, paired: bool):
    plan = host.make_probe_pair_plan((("bridge", "pair"),), slots=64)
    observation = plan["observations"][0]
    if not paired:
        observation["exit_capture_requirement"] = "none"
        observation["entry"]["reads"] = [row for row in observation["entry"]["reads"]
                                                   if row.get("phase") != "leave"]
    if not paired:
        observation["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 16}
    return plan


def main():
    root = ROOT / "test-output" / ("native-pair-gate-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    try:
        discovery = plan_for(host, False)
        discovery_path=root/"discovery-plan.json";discovery_path.write_bytes(canonical(discovery))
        host.control("apply", plan=discovery)
        host.invoke("pair_stress", count=5)
        discovered = host.stop()
        summary = discovered["retention"][0]
        manifest, errors = read_manifest(Path(discovered["directory"]) / "session.manifest")
        if errors or len(summary["keys"]) != 1:
            raise AssertionError((errors, summary))
        activation = next(row for row in manifest if row.get("kind") == "plan_activation")
        module_base = activation["bindings"][0]["module_base"]
        exact_return = summary["keys"][0]["entry_return_address"]

        target=plan_for(host,True);target_path=root/"target-pair-plan.json";target_path.write_bytes(canonical(target))
        selection_path=root/"selection.json";selection_path.write_bytes(canonical({
            "schema":"uc.exact-caller-selection.v1","points":[{"point":"bridge","callers":[{
                "module":"fixture","return_rva":exact_return-module_base,"evidence":["fixture"]}]}]}))
        derived=root/"derived";derive(discovery_path,Path(discovered["directory"]),selection_path,derived,target_path)
        gated=json.loads((derived/"capture-plan.exact-callers.json").read_text(encoding="utf-8"))
        host.control("apply", plan=gated)
        host.invoke("pair_stress", count=10)
        host.invoke("pair", add=1)  # A second caller remains aggregate-only.
        stopped = host.stop()
        events = [event for event, _ in records(stopped["directory"])]
        kinds = [event["kind"] for event in events]
        retained = stopped["retention"][0]
        if kinds.count("enter") != 10 or kinds.count("leave") != 10 or \
                kinds.count("aggregate_entry_sample") != 1:
            raise AssertionError(kinds)
        if retained["callbacks"] != 11 or retained["exact_promoted_callbacks"] != 10 or \
                retained["exact_promoted_records_persisted"] != 10 or \
                retained["exact_entries_persisted"] != 10 or \
                retained["exact_normal_exits_persisted"] != 10 or \
                retained["exact_pairs_persisted"] != 10 or \
                not retained["classified_exact_records_complete_so_far"]:
            raise AssertionError(retained)
        exact_events = [row for row in events if row.get("retention_key", {}).get("lane") == "exact_promoted"]
        if len(exact_events) != 20 or any(
                row["retention_key"].get("kind") != "entry_return_address"
                or not isinstance(row["retention_key"].get("value"), int)
                for row in exact_events):
            raise AssertionError(exact_events)
        if any(not isinstance(row.get("raw_abi", {}).get("stack_marker"), int)
               or row["raw_abi"]["stack_marker"] == 0 for row in exact_events):
            raise AssertionError("UCEVT003 stack markers were not preserved in the JSON projection")
        if sum(row["count"] for row in retained["keys"]) != 11 or len(retained["keys"]) != 2:
            raise AssertionError(retained)
        report = {"ok": True, "callbacks": 11, "exact_pairs": 10,
                  "aggregate_entry_samples": 1, "stored_events": len(events),
                  "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
