from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest
import hashlib
import json
import tempfile

from p1_apply_entry_qualification import (derive_entry_qualified_manifest,
                                          bind_runtime_predicates,
                                          qualification_module_bases,
                                          qualified_evidence_refs,
                                          qualified_source_table,
                                          validate_qualification_scope)
from p1_merge_entry_plans import run as merge_entry_plans


class CampaignQualificationTests(unittest.TestCase):
    def test_entry_qualification_does_not_promote_exit_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "qualification.json"
            evidence.write_text("{}", encoding="utf-8")
            manifest = {"schema": "uc.native-exit-manifest.v1",
                "status": "mechanical-candidate", "functions": [{
                    "function_id": "F", "module": "m", "entry_rva": 1,
                    "runtime_functions": [{"runtime_function_role": "primary"}],
                    "normal_exits": [], "terminal_sites": [],
                    "completeness": {"normal_exit_set_complete": False,
                                     "tail_set_complete": False,
                                     "cold_fragments_complete": False}}]}
            identity = {"pid": 7, "creation_time_100ns": 11}
            derived = derive_entry_qualified_manifest(manifest, evidence, identity)
            self.assertEqual(derived["status"], "partially-verified")
            self.assertEqual(derived["qualification_scope"], "entry-only")
            self.assertTrue(derived["entry_activation_ready"])
            self.assertFalse(derived["exit_activation_ready"])
            self.assertEqual(derived["functions"][0]["completeness"],
                             manifest["functions"][0]["completeness"])
            self.assertEqual(manifest["status"], "mechanical-candidate")

    def test_exact_scope_remains_default(self):
        validate_qualification_scope({"a": 1}, {"a": 2}, {"a"}, False)
        with self.assertRaisesRegex(ValueError, "exactly cover source plan"):
            validate_qualification_scope({"a": 1, "b": 1}, {"a": 2, "b": 2}, {"a"}, False)

    def test_explicit_superset_can_feed_subplans(self):
        validate_qualification_scope({"a": 1, "b": 1}, {"a": 2, "b": 2}, {"a"}, True)
        with self.assertRaisesRegex(ValueError, "every source plan"):
            validate_qualification_scope({"a": 1}, {"a": 2}, {"a", "b"}, True)

    def test_response_must_cover_whole_request_even_for_subplan(self):
        with self.assertRaisesRegex(ValueError, "exactly cover its request"):
            validate_qualification_scope({"a": 1, "b": 1}, {"a": 2}, {"a"}, True)

    def test_target_qualification_preserves_field_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "game.dll"
            fields = root / "fields.txt"
            qualification = root / "qualification.json"
            module.write_bytes(b"module")
            fields.write_bytes(b"runtime field harvest")
            qualification.write_bytes(b"qualification")
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            plan = {
                "sources": {
                    "game-module": {"path": str(module), "sha256": digest(module)},
                    "runtime-field-layout": {"path": str(fields), "sha256": digest(fields)},
                },
                "points": [{"module": "game"}],
            }
            manifest_sources = {"game": {"path": str(module), "sha256": digest(module)}}
            table = qualified_source_table(plan, manifest_sources, qualification)
            self.assertEqual(set(table), {
                "game-module", "runtime-field-layout", "target-qualification"
            })
            self.assertEqual(
                qualified_evidence_refs(["runtime-field-layout"], "game"),
                ["runtime-field-layout", "game-module", "target-qualification"],
            )

    def test_runtime_predicate_binds_module_rva_after_qualification(self):
        plan = {"points": [{"id": "invoker", "reads": [{
            "id": "code-target", "op": "register", "base": "rcx",
            "phase": "enter", "width": 8, "evidence": ["static-api"],
        }], "runtime_predicates": [{
            "read_id": "code-target", "op": "eq", "module": "game",
            "rva": 0x1234, "evidence": ["static-api"],
        }]}]}
        response = {"sites": [
            {"module": "game", "module_base": 0x180000000},
            {"module": "game", "module_base": 0x180000000},
        ]}
        bound, rows = bind_runtime_predicates(plan, response)
        read = bound["points"][0]["reads"][0]
        self.assertEqual(read["when"], {"op": "eq", "value": 0x180001234})
        self.assertIn("runtime-predicate-bindings", read["evidence"])
        self.assertNotIn("runtime_predicates", bound["points"][0])
        self.assertEqual(rows[0]["resolved_value"], 0x180001234)

    def test_runtime_predicate_rejects_inconsistent_module_bases(self):
        with self.assertRaisesRegex(ValueError, "inconsistent module bases"):
            qualification_module_bases({"sites": [
                {"module": "game", "module_base": 0x1000},
                {"module": "game", "module_base": 0x2000},
            ]})

    def test_merge_verifies_used_sources_and_prunes_retired_unused_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"authoritative")
            source = {"path": str(evidence), "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
            plans = []
            for index in range(2):
                plan = {"schema": "uc.capture-plan.v1", "plan_id": f"p{index}", "plan_revision": 1,
                    "modules": {"m": {"image": "m.dll", "sha256": "1" * 64}},
                    "sources": {"used": source,
                                "retired-unused": {"path": str(root / "gone.cpp"), "sha256": "2" * 64}},
                    "resources": {"slots_per_point": 2, "max_record_bytes": 16},
                    "points": [{"id": f"f{index}", "backend": "gum_probe", "module": "m",
                                "rva": 0x100 + index * 0x20, "expected_prefix": "90" * 16,
                                "evidence": ["used"], "reads": []}]}
                path = root / f"p{index}.json"
                path.write_text(json.dumps(plan), encoding="utf-8")
                plans.append(path)
            output = root / "merged.json"
            result = merge_entry_plans(plans, "merged", output)
            merged = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["points"], 2)
            self.assertEqual(set(merged["sources"]), {"used"})


if __name__ == "__main__":
    unittest.main()
