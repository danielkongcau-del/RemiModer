from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest
import hashlib
import json
import tempfile

from p1_apply_entry_qualification import validate_qualification_scope
from p1_merge_entry_plans import run as merge_entry_plans


class CampaignQualificationTests(unittest.TestCase):
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
