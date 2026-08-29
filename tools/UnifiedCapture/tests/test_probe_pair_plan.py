from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from uc.model import canonical
from uc.probe_pair import compile_probe_pair


HASH = "1" * 64


def patch(span=5):
    return {"backend_build_hash": HASH, "redirect_kind": "near", "required_redirect_span": span,
            "relocated_span": span, "fault_in_relocated_span_test": "passed-own-fixture",
            "architectural_rsp_test": "passed-own-fixture", "cet_cfg_test": "target-runtime-required"}


def manifest(entry=0x100, probe=0x180):
    return {"schema": "uc.native-exit-manifest.v1", "status": "three-way-verified",
            "backend_capability": {"backend_build_hash": HASH},
            "functions": [{"function_id": "F", "module": "fixture", "entry_rva": entry,
                "runtime_functions": [{"runtime_function_role": "primary"}],
                "normal_exits": [{"exit_site_id": "ret", "terminal_semantics": "normal_return",
                    "terminal_semantics_verified": True, "probe_candidates": [{
                        "probe_rva": probe, "expected_bytes": "4883c428c3",
                        "verified_source_prefix": "4883c428c3" + "90" * 11,
                        "incoming_edges_complete": True,
                        "backend_patch_contract": dict(patch(), probe_rva=probe),
                        "exit_capture_contract": {"probe_semantics": "pre_instruction",
                            "return_value_stable": True, "xmm_return_stable": True,
                            "stack_restored": False, "caller_return_slot_valid": False,
                            "stack_adjust_remaining": 40, "nonvolatile_restore_remaining": [],
                            "relocation_class": "pure_epilogue", "exception_neutral_relocation": True,
                            "contract_evidence": ["fixture"]}}]}], "terminal_sites": [],
                "completeness": {"normal_exit_set_complete": True, "tail_set_complete": True,
                                 "cold_fragments_complete": True}}]}


class ProbePairPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uc-probe-pair-plan-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source.bin"
        self.source.write_bytes(b"source")

    def tearDown(self):
        self.temp.cleanup()

    def make_plan(self, observations=1, *, requirement="completion", exit_manifest=None):
        exit_manifest = exit_manifest or manifest()
        path = self.root / "exit.json"
        path.write_bytes(canonical(exit_manifest))
        source_sha = hashlib.sha256(self.source.read_bytes()).hexdigest()
        manifest_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        obs = {"id": "obs", "backend": "gum_function_probe_pair", "module": "fixture",
               "entry": {"rva": 0x100, "expected_prefix": "90" * 16,
                         "backend_patch_contract": patch(), "reads": []},
               "exit_capture_requirement": requirement,
               "native_exit_manifest": {"path": str(path), "sha256": manifest_sha, "function_id": "F"},
               "evidence": ["fixture"]}
        rows = []
        for index in range(observations):
            item = copy.deepcopy(obs)
            item["id"] = f"obs-{index}"
            rows.append(item)
        return {"schema": "uc.capture-plan.v2", "plan_id": "fixture", "plan_revision": 1,
                "modules": {"fixture": {"image": "fixture.dll", "sha256": "2" * 64}},
                "sources": {"fixture": {"path": str(self.source), "sha256": source_sha}},
                "resources": {"event_slots_per_observation": 8, "call_frames_per_function": 8,
                              "thread_nesting_limit": 32, "max_record_bytes": 4096},
                "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                         "partial_overlap": "reject"},
                "observations": rows}

    def test_exact_sites_share_one_physical_listener(self):
        compiled = compile_probe_pair(self.make_plan(2))
        self.assertEqual(len(compiled.sites), 2)
        self.assertEqual([len(site.subscriptions) for site in compiled.sites], [2, 2])

    def test_entry_only_does_not_activate_exit(self):
        compiled = compile_probe_pair(self.make_plan(requirement="none"))
        self.assertEqual(len(compiled.sites), 1)
        self.assertEqual(compiled.sites[0].subscriptions[0].role, "entry")

    def test_partial_overlap_rejected(self):
        value = self.make_plan(2)
        value["observations"][1]["entry"]["rva"] = 0x102
        value["observations"][1]["native_exit_manifest"]["function_id"] = "G"
        path = Path(value["observations"][1]["native_exit_manifest"]["path"])
        data = manifest()
        second = copy.deepcopy(data["functions"][0])
        second["function_id"] = "G"
        second["entry_rva"] = 0x102
        data["functions"].append(second)
        path.write_bytes(canonical(data))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        for row in value["observations"]:
            row["native_exit_manifest"]["sha256"] = digest
        with self.assertRaisesRegex(ValueError, "overlap"):
            compile_probe_pair(value)

    def test_incomplete_incoming_edges_block_activation(self):
        data = manifest()
        data["functions"][0]["normal_exits"][0]["probe_candidates"][0]["incoming_edges_complete"] = False
        with self.assertRaisesRegex(ValueError, "incoming edge coverage"):
            compile_probe_pair(self.make_plan(exit_manifest=data))

    def test_unqualified_relocation_blocks_activation(self):
        data = manifest()
        data["functions"][0]["normal_exits"][0]["probe_candidates"][0]["exit_capture_contract"]["exception_neutral_relocation"] = None
        with self.assertRaisesRegex(ValueError, "exception-neutral"):
            compile_probe_pair(self.make_plan(exit_manifest=data))

    def test_manifest_hash_is_mandatory_even_without_source_verification(self):
        value = self.make_plan()
        value["observations"][0]["native_exit_manifest"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "manifest changed"):
            compile_probe_pair(value, verify_sources=False)


if __name__ == "__main__":
    unittest.main()
