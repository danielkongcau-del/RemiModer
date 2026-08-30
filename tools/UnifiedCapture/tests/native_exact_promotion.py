"""Discover one fixture caller, then deterministically promote it to exact records."""
from __future__ import annotations

import json
import copy
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from exact_caller_promotion_plan import derive
from uc.model import canonical
from uc.store import inspect_session, read_manifest
from retained_caller_inventory import run as inventory_run
from retained_exact_selection import run as selection_run


def retained_plans(host: Host):
    target = host.make_probe_pair_plan((("bridge/entry", "pair"),), slots=64)
    discovery = copy.deepcopy(target)
    discovery["plan_id"] = "fixture-retained-v2"
    observation = discovery["observations"][0]
    observation["exit_capture_requirement"] = "none"
    observation["entry"]["reads"] = [row for row in observation["entry"]["reads"]
                                               if row.get("phase") != "leave"]
    observation["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 16}
    target["plan_id"] += "-qualified-target"
    return discovery, target


def main():
    root = ROOT / "test-output" / ("native-exact-promotion-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    try:
        discovery, target = retained_plans(host)
        discovery_path = root / "discovery-plan.json"
        discovery_path.write_bytes(canonical(discovery))
        host.control("apply", plan=discovery)
        host.invoke("pair_stress", count=5)
        discovered = host.stop()
        summary = discovered["retention"][0]
        if len(summary["keys"]) != 1 or summary["keys"][0]["count"] != 5:
            raise AssertionError(summary)
        manifest, errors = read_manifest(Path(discovered["directory"]) / "session.manifest")
        if errors:
            raise AssertionError(errors)
        activation = next(row for row in manifest if row.get("kind") == "plan_activation")
        module_base = activation["bindings"][0]["module_base"]
        return_address = summary["keys"][0]["entry_return_address"]
        if return_address < module_base:
            raise AssertionError((return_address, module_base))

        # Exercise the production v2 acceptance -> inventory -> selection ->
        # promotion identity chain. The portable point id is bridge while the
        # activated/manifest observation id is bridge/entry.
        acceptance_path = root / "entry-acceptance.json"
        acceptance_path.write_bytes(canonical({
            "schema": "uc.entry-evidence-acceptance.v2",
            "session": {"inspection": inspect_session(discovered["directory"])},
            "points": [{"point": "bridge/entry", "retention_generation": summary,
                "runtime_caller_evidence": [{"return_address": return_address,
                    "module": "fixture", "return_rva": return_address - module_base,
                    "module_membership": "INSIDE_BOUND_MODULE",
                    "callsite_status": "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"}]}],
        }))
        inventory = inventory_run(acceptance_path, root / "inventory")
        selection_report = selection_run(Path(root / "inventory" / "retained-caller-inventory.json"),
                                         root / "selection")
        selection_path = Path(selection_report["selection"]["path"])
        selected = json.loads(selection_path.read_text(encoding="utf-8"))
        if selected["points"][0].get("source_observation_point") != "bridge/entry":
            raise AssertionError(selected)
        target_path = root / "target-plan.json"
        target_path.write_bytes(canonical(target))
        derived_root = root / "derived"
        derive(discovery_path, Path(discovered["directory"]), selection_path, derived_root, target_path)
        exact = json.loads((derived_root / "capture-plan.exact-callers.json").read_text(encoding="utf-8"))
        if exact["observations"][0]["id"] != "bridge/entry":
            raise AssertionError("cross-plan entry identity join failed")
        host.control("apply", plan=exact)
        host.invoke("pair_stress", count=20)
        stopped = host.stop()
        promoted = stopped["retention"][0]
        events = [event for event, _ in records(stopped["directory"])]
        if promoted["exact_promoted_callbacks"] != 20 or \
                promoted["exact_promoted_records_persisted"] != 20 or \
                promoted["exact_pairs_persisted"] != 20 or \
                not promoted["classified_exact_records_complete_so_far"]:
            raise AssertionError(promoted)
        if len(events) != 40 or any(event.get("retention_key", {}).get("lane") != "exact_promoted"
                                    for event in events):
            raise AssertionError(events)
        report = {"ok": True, "discovery_callbacks": 5, "exact_callbacks": 20,
                  "exact_records": len(events), "return_rva": return_address - module_base,
                  "game_runtime_verified": False}
    finally:
        host.close()
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(root / "report.json"), **report}))


if __name__ == "__main__":
    main()
