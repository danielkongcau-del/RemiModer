from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from retained_caller_inventory import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_inventory_preserves_counts_without_making_selection(tmp_path: Path) -> None:
    address = 0x180012345
    acceptance = {
        "schema": "uc.entry-evidence-acceptance.v2",
        "session": {"inspection": {"storage_complete": True,
                                      "cleanup": "STOPPED_CLEAN", "errors": []}},
        "points": [{
            "point": "hot/entry",
            "retention_generation": {"callbacks": 7, "complete_for_caller_counts": True,
                "keys": [{"entry_return_address": address, "count": 7,
                          "first_qpc": 10, "last_qpc": 20, "full_records_persisted": 1}]},
            "runtime_caller_evidence": [{"return_address": address, "module": "fixture",
                "module_membership": "INSIDE_BOUND_MODULE", "return_rva": 0x12345,
                "callsite_status": "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL",
                "callsite_rva": 0x12340, "call_kind": "direct", "representative_event_id": 3}],
        }],
    }
    result = run(_write(tmp_path / "acceptance.json", acceptance), tmp_path / "out")
    assert result["all_retained_points_complete"] is True
    assert result["totals"] == {"retained_points": 1, "classified_callers": 1,
        "callbacks": 7, "exact_promotion_eligible": 1}
    candidate = result["points"][0]["candidates"][0]
    assert candidate["selection_row_template"] == {
        "module": "fixture", "return_rva": 0x12345, "evidence": []}
    assert result["authority"]["selection"] == "NOT_PERFORMED"


def test_inventory_rejects_non_retained_acceptance(tmp_path: Path) -> None:
    acceptance = {"schema": "uc.entry-evidence-acceptance.v2",
                  "session": {"inspection": {"storage_complete": True,
                                                "cleanup": "STOPPED_CLEAN", "errors": []}},
                  "points": []}
    with pytest.raises(ValueError, match="no retained caller summaries"):
        run(_write(tmp_path / "acceptance.json", acceptance), tmp_path / "out")
