from __future__ import annotations

import copy
import unittest

from uc.site_qualification import validate_site_qualification


def fixture():
    return {"schema": "uc.probe-site-qualification.v1", "qualification_id": "q",
            "modules": {"m": {"image": "m.dll", "sha256": "1" * 64}},
            "sites": [{"id": "a", "module": "m", "rva": 0x100,
                       "verified_source_prefix": "90" * 32, "semantic_safe_span": 16,
                       "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True}]}


class SiteQualificationTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_site_qualification(fixture())["sites"], 1)

    def test_overlap_rejected(self):
        value = fixture()
        other = copy.deepcopy(value["sites"][0]);other.update(id="b", rva=0x108)
        value["sites"].append(other)
        with self.assertRaisesRegex(ValueError, "overlap"):
            validate_site_qualification(value)

    def test_partial_safety_claim_rejected(self):
        value = fixture();value["sites"][0]["safe_redirect_spans"] = [5]
        with self.assertRaisesRegex(ValueError, "exactly"):
            validate_site_qualification(value)


if __name__ == "__main__":
    unittest.main()
