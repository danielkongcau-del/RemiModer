from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_dispatch_role_fingerprint import _classify


def test_classifies_only_when_all_shape_matches_agree() -> None:
    target = {"shape_sha256": "a"}
    refs = [{"serialized_type": "A", "method": "M", "role": "wrapper",
             "fingerprint": {"shape_sha256": "a", "rva": 1}},
            {"serialized_type": "B", "method": "M", "role": "wrapper",
             "fingerprint": {"shape_sha256": "a", "rva": 2}}]
    result = _classify(target, refs)
    assert result["status"] == "STRUCTURALLY_CLASSIFIED"
    assert result["derived_role"] == "wrapper"


def test_conflicting_reference_roles_remain_unresolved() -> None:
    target = {"shape_sha256": "a"}
    refs = [{"serialized_type": "A", "method": "M", "role": "wrapper",
             "fingerprint": {"shape_sha256": "a", "rva": 1}},
            {"serialized_type": "B", "method": "M", "role": "nativeImplementation",
             "fingerprint": {"shape_sha256": "a", "rva": 2}}]
    result = _classify(target, refs)
    assert result["status"] == "UNRESOLVED"
    assert result["derived_role"] is None
