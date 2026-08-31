from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_executor_coverage_ledger import _dispatch_shape, _runtime_rows


def test_dispatch_shapes_stay_evidence_bounded() -> None:
    assert _dispatch_shape({"nativeIdentityAndDispatch": {"dispatch": {
        "wrapper": {}, "nativeImplementation": {}}}}) == "ACTION_WRAPPER_AND_NATIVE_IMPLEMENTATION"
    assert _dispatch_shape({"nativeIdentityAndDispatch": {"dispatch": {
        "executorClass": "X", "factory": {}, "operationalMethods": []}}}) == "EXECUTOR_CLASS_WITH_FACTORY"
    assert _dispatch_shape({"nativeIdentityAndDispatch": {"dispatch": {
        "operationalMethods": []}}}) == "OPERATIONAL_METHODS_ONLY"
    assert _dispatch_shape({"nativeIdentityAndDispatch": {}}) == "NO_DISPATCH_JOIN"


def test_runtime_role_join_does_not_invent_unobserved_types() -> None:
    joined = _runtime_rows({"ability_action_entries": [{
        "serialized_type": "ActionA",
        "dispatch_role_status": "SOURCE_CLASSIFIED",
        "capture_policy": "bounded",
        "roles": {
            "wrapper": {"method": "HCB", "rva": 1, "status": "OBSERVED"},
            "native_implementation": {"method": "BHCI", "rva": 2, "status": "NOT_OBSERVED"},
        },
    }]})
    assert set(joined) == {"ActionA"}
    assert joined["ActionA"]["roles"]["wrapper"]["status"] == "OBSERVED"
    assert "ActionB" not in joined
