from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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

    def test_return_address_retention_is_explicit_bounded_and_entry_only(self):
        value = self.make_plan(requirement="none")
        value["observations"][0]["retention"] = {
            "mode": "first_per_entry_return_address", "max_keys": 1024,
            "exact_callers": [{"module": "fixture", "return_rva": 0x220,
                               "evidence": ["fixture"]}]}
        self.assertEqual(len(compile_probe_pair(value).sites), 1)
        for capacity, message in ((0, "nonzero power"), (3, "power of two"), (131072, "<= 65536")):
            broken = copy.deepcopy(value)
            broken["observations"][0]["retention"]["max_keys"] = capacity
            with self.subTest(capacity=capacity), self.assertRaisesRegex(ValueError, message):
                compile_probe_pair(broken)
        paired = self.make_plan(requirement="completion")
        paired["observations"][0]["retention"] = value["observations"][0]["retention"]
        self.assertEqual(len(compile_probe_pair(paired).sites), 2)
        ungated_pair = copy.deepcopy(paired)
        del ungated_pair["observations"][0]["retention"]["exact_callers"]
        with self.assertRaisesRegex(ValueError, "requires an exact caller gate"):
            compile_probe_pair(ungated_pair)
        predicated = copy.deepcopy(value)
        predicated["observations"][0]["entry"]["reads"] = [{"id": "receiver", "base": "rcx",
            "op": "scalar", "width": 8, "phase": "enter", "when": {"op": "neq", "value": 0},
            "evidence": ["fixture"]}]
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            compile_probe_pair(predicated)
        duplicate = copy.deepcopy(value)
        duplicate["observations"][0]["retention"]["exact_callers"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate exact caller"):
            compile_probe_pair(duplicate)
        missing_evidence = copy.deepcopy(value)
        missing_evidence["observations"][0]["retention"]["exact_callers"][0]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "lacks existing evidence"):
            compile_probe_pair(missing_evidence)

    def test_composite_retention_uses_only_bounded_raw_key_parts(self):
        value = self.make_plan(requirement="none")
        value["observations"][0]["retention"] = {
            "mode": "first_per_composite_key", "max_keys": 1024,
            "key": [
                {"kind": "entry_return_address", "evidence": ["fixture"]},
                {"kind": "register", "register": "rcx", "mask": 0xfffffffffffffff0,
                 "evidence": ["fixture"]},
            ],
        }
        self.assertEqual(len(compile_probe_pair(value).sites), 1)
        for mutation, message in ((lambda key: key.reverse(), "must begin"),
                                  (lambda key: key.append(copy.deepcopy(key[-1])), "duplicate")):
            broken = copy.deepcopy(value)
            mutation(broken["observations"][0]["retention"]["key"])
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                compile_probe_pair(broken)
        missing = copy.deepcopy(value)
        missing["observations"][0]["retention"]["key"][1]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "lacks existing evidence"):
            compile_probe_pair(missing)

    def test_partial_overlap_rejected(self):
        value = self.make_plan(2)
        # Near redirects change only five bytes, but Gum owns a 16-byte
        # relocation window. +8 must therefore still be rejected.
        value["observations"][1]["entry"]["rva"] = 0x108
        value["observations"][1]["native_exit_manifest"]["function_id"] = "G"
        path = Path(value["observations"][1]["native_exit_manifest"]["path"])
        data = manifest()
        second = copy.deepcopy(data["functions"][0])
        second["function_id"] = "G"
        second["entry_rva"] = 0x108
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

    def test_phase_read_program_matches_native_base_and_dependency_rules(self):
        value = self.make_plan()
        reads = value["observations"][0]["entry"]["reads"]
        reads.extend([
            {"id": "global", "base": "module:fixture", "offset": 32, "op": "scalar",
             "width": 8, "phase": "enter", "evidence": ["fixture"]},
            {"id": "child", "base": "global", "op": "block", "size": 16,
             "phase": "enter", "evidence": ["fixture"]},
            {"id": "receiver-after", "base": "entry:rcx", "op": "scalar", "width": 8,
             "phase": "leave", "evidence": ["fixture"]},
            {"id": "leave-child", "base": "receiver-after", "op": "block", "size": 8,
             "phase": "leave", "evidence": ["fixture"]},
        ])
        self.assertEqual(len(compile_probe_pair(value).sites), 2)

        for mutate, message in (
            (lambda rows: rows[1].update(phase="leave"), "selected phase"),
            (lambda rows: rows.append({"id": "grandchild", "base": "child", "op": "scalar",
                                       "width": 8, "phase": "enter", "evidence": ["fixture"]}), "dependency"),
            (lambda rows: rows[1].update(size=0), "block size"),
            (lambda rows: rows[2].update(phase="enter"), "leave-phase only"),
            (lambda rows: rows[2].update(when={"op": "eq", "value": 1}), "enter-phase"),
        ):
            broken = copy.deepcopy(value)
            mutate(broken["observations"][0]["entry"]["reads"])
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                compile_probe_pair(broken)

    def test_leave_reads_require_exits_and_use_a_per_phase_budget(self):
        entry_only = self.make_plan(requirement="none")
        entry_only["observations"][0]["entry"]["reads"].append(
            {"id": "after", "base": "entry:rcx", "op": "scalar", "width": 8,
             "phase": "leave", "evidence": ["fixture"]})
        with self.assertRaisesRegex(ValueError, "exit capture requirement"):
            compile_probe_pair(entry_only)

        value = self.make_plan()
        value["resources"]["max_record_bytes"] = 16
        value["observations"][0]["entry"]["reads"] = [
            {"id": "before", "base": "module:fixture", "op": "block", "size": 16,
             "phase": "enter", "evidence": ["fixture"]},
            {"id": "after", "base": "module:fixture", "op": "block", "size": 16,
             "phase": "leave", "evidence": ["fixture"]},
        ]
        self.assertEqual(len(compile_probe_pair(value).sites), 2)
        value["observations"][0]["entry"]["reads"].append(
            {"id": "too-much-after", "base": "module:fixture", "op": "scalar", "width": 1,
             "phase": "leave", "evidence": ["fixture"]})
        with self.assertRaisesRegex(ValueError, "per-phase"):
            compile_probe_pair(value)

    def test_register_value_read_and_predicate_do_not_dereference(self):
        value = self.make_plan()
        value["observations"][0]["entry"]["reads"] = [
            {"id": "parameter-id", "base": "rdx", "op": "register", "width": 4,
             "phase": "enter", "when": {"op": "eq", "value": 0x1234},
             "evidence": ["fixture"]},
            {"id": "receiver-after", "base": "entry:rcx", "op": "register", "width": 8,
             "phase": "leave", "evidence": ["fixture"]},
        ]
        self.assertEqual(len(compile_probe_pair(value).sites), 2)
        for mutate, message in (
            (lambda read: read.update(base="global"), "current/entry register"),
            (lambda read: read.update(offset=1), "zero offset"),
        ):
            broken = copy.deepcopy(value)
            mutate(broken["observations"][0]["entry"]["reads"][0])
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                compile_probe_pair(broken)

    def test_bounded_in_predicate(self):
        value = self.make_plan()
        value["observations"][0]["entry"]["reads"] = [
            {"id": "parameter-id", "base": "rdx", "op": "register", "width": 4,
             "phase": "enter", "when": {"op": "in", "values": [1, 3, 5]},
             "evidence": ["fixture"]},
        ]
        self.assertEqual(len(compile_probe_pair(value).sites), 2)
        for values in ([], [1] * 2, list(range(17))):
            broken = copy.deepcopy(value)
            broken["observations"][0]["entry"]["reads"][0]["when"]["values"] = values
            with self.subTest(values=len(values)), self.assertRaisesRegex(ValueError, "1..16 unique"):
                compile_probe_pair(broken)

    def test_resource_and_redirect_contracts_match_native_compiler(self):
        for mutate, message in (
            (lambda value: value["resources"].update(max_record_bytes=0), "max_record_bytes"),
            (lambda value: value["resources"].update(call_frames_per_function=257), "native maximum"),
            (lambda value: value["resources"].update(thread_nesting_limit=257), "native maximum"),
            (lambda value: value["observations"][0]["entry"]["backend_patch_contract"].update(
                redirect_kind="far", required_redirect_span=5), "redirect"),
            (lambda value: value["observations"][0]["entry"]["backend_patch_contract"].update(
                relocated_span=17), "redirect"),
        ):
            value = self.make_plan()
            mutate(value)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                compile_probe_pair(value)


if __name__ == "__main__":
    unittest.main()
