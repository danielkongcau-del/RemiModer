from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_slot_owner_scan_analyze import MATCH


def test_match_preserves_empty_native_method_name_as_positive_evidence() -> None:
    row = MATCH.fullmatch(
        "MATCH|type=339|token=0x2000154|namespace=|class=Type|index=201|"
        "name=|rva=0x1d1923c0|slot=0x1d1923c0|method-info=0000050001631E30"
    )
    assert row is not None
    assert row.group(4) == "Type"
    assert row.group(6) == ""
