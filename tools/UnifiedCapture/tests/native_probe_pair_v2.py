"""End-to-end native v2 probe-pair test on explicit assembly fixtures only."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from uc.model import canonical
from uc.probe_pair import compile_probe_pair
from uc.store import inspect_session


GUM_HASH = "23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475"


def patch(probe_rva=None):
    value = {"backend_build_hash": GUM_HASH, "redirect_kind": "near", "required_redirect_span": 5,
             "relocated_span": 5, "fault_in_relocated_span_test": "passed-own-fixture",
             "architectural_rsp_test": "passed-own-fixture", "cet_cfg_test": "target-runtime-required"}
    if probe_rva is not None:
        value["probe_rva"] = probe_rva
    return value


def function(fid, entry, exit):
    contract = {"probe_semantics": "pre_instruction", "return_value_stable": True,
                "xmm_return_stable": True, "stack_restored": True,
                "caller_return_slot_valid": True, "stack_adjust_remaining": 0,
                "nonvolatile_restore_remaining": [], "relocation_class": "pure_epilogue",
                "exception_neutral_relocation": True, "contract_evidence": ["assembly-fixture"]}
    return {"function_id": fid, "module": "fixture", "entry_rva": entry["rva"],
            "runtime_functions": [{"runtime_function_role": "primary"}],
            "normal_exits": [{"exit_site_id": f"{fid}-ret", "terminal_semantics": "normal_return",
                "terminal_semantics_verified": True, "probe_candidates": [{"probe_rva": exit["rva"],
                    "expected_bytes": exit["expected_prefix"][:10],
                    "verified_source_prefix": exit["expected_prefix"], "incoming_edges_complete": True,
                    "backend_patch_contract": patch(exit["rva"]), "exit_capture_contract": contract}]}],
            "terminal_sites": [], "completeness": {"normal_exit_set_complete": True,
                "tail_set_complete": True, "cold_fragments_complete": True}}


def main():
    root = ROOT / "test-output" / ("native-probe-pair-v2-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        targets = host.info["targets"]
        functions = [
            function("pair", targets["pair_entry"], targets["pair_exit"]),
            function("recursive", targets["pair_recursive_entry"], targets["pair_recursive_exit"]),
            function("block", targets["pair_block_entry"], targets["pair_block_exit"]),
        ]
        manifest = {"schema": "uc.native-exit-manifest.v1", "status": "three-way-verified",
                    "backend_capability": {"backend_build_hash": GUM_HASH}, "functions": functions}
        manifest_path = root / "fixture-exit-manifest.json"
        manifest_path.write_bytes(canonical(manifest))
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        plan = {"schema": "uc.capture-plan.v2", "plan_id": "native-probe-pair-fixture",
                "plan_revision": 17,
                "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
                "sources": {"fixture": {"path": host.info["module_path"], "sha256": host.info["sha256"]}},
                "resources": {"event_slots_per_observation": 64, "call_frames_per_function": 16,
                              "thread_nesting_limit": 64, "max_record_bytes": 256},
                "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                         "partial_overlap": "reject"}, "observations": []}

        def observation(oid, fid, target):
            return {"id": oid, "backend": "gum_function_probe_pair", "module": "fixture",
                    "entry": {"rva": target["rva"], "expected_prefix": target["expected_prefix"],
                              "backend_patch_contract": patch(), "reads": [{"id": "receiver",
                                  "base": "rcx", "op": "scalar", "width": 8, "phase": "enter",
                                  "evidence": ["fixture"]}]},
                    "exit_capture_requirement": "return_value",
                    "native_exit_manifest": {"path": str(manifest_path), "sha256": manifest_sha,
                                             "function_id": fid}, "evidence": ["fixture"]}

        plan["observations"] = [observation("pair-a", "pair", targets["pair_entry"]),
                                observation("pair-b", "pair", targets["pair_entry"]),
                                observation("recursive", "recursive", targets["pair_recursive_entry"]),
                                observation("block", "block", targets["pair_block_entry"])]
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
        host.invoke("pair", add=3)
        host.invoke("pair_recursive", depth=3)
        host.invoke("release")
        stopped = host.stop()
        rows = [event for event, _ in records(stopped["directory"])]
        by_point = {name: [row for row in rows if row["point"] == name]
                    for name in ("pair-a", "pair-b", "recursive", "block")}
        if any([row["kind"] for row in by_point[name]] != ["enter", "leave"] for name in ("pair-a", "pair-b")):
            raise AssertionError(by_point)
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
                  "inspection": inspection, "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **{key: result[key] for key in
              ("ok", "events", "normal_leaves") if key in result}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
