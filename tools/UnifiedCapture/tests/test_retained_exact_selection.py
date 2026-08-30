from __future__ import annotations

import json
from pathlib import Path

import pytest

from retained_exact_selection import run
from uc.model import canonical


def inventory(clean=True):
    return {"schema": "uc.retained-caller-inventory.v1", "session_clean": clean,
        "all_retained_points_complete": clean, "points": [{"point": "bridge/entry",
            "source_plan_point": "bridge", "candidates": [
                {"module": "fixture", "return_rva": 0x220, "exact_promotion_eligible": True,
                 "ineligibility_reasons": []},
                {"module": None, "return_rva": None, "exact_promotion_eligible": False,
                 "ineligibility_reasons": ["RETURN_PREDECESSOR_NOT_PROVEN_CALL"]}]}]}


def test_selects_all_eligible_by_source_plan_identity(tmp_path: Path):
    source = tmp_path / "inventory.json";source.write_bytes(canonical(inventory()))
    report = run(source, tmp_path / "out")
    selected = json.loads(Path(report["selection"]["path"]).read_text())
    assert selected["points"] == [{"point": "bridge", "callers": [
        {"module": "fixture", "return_rva": 0x220, "evidence": []}]}]
    assert report["ineligible_not_selected"] == 1
    assert report["semantic_identity_inferred"] is False


def test_refuses_incomplete_inventory(tmp_path: Path):
    source = tmp_path / "inventory.json";source.write_bytes(canonical(inventory(False)))
    with pytest.raises(ValueError, match="complete and clean"):
        run(source, tmp_path / "out")
