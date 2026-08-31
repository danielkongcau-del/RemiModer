from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_dynamic_target_owner_harvest_prepare import build
from uc.model import canonical


def test_prepare_selects_only_unresolved_targets(tmp_path: Path) -> None:
    method = tmp_path / "method.json"
    method.write_bytes(canonical({
        "schema": "uc.ability-dynamic-dispatch-authoritative-method-join.v1",
        "targets": [{"target_rva": 0x100, "method_candidates": []},
                    {"target_rva": 0x200, "method_candidates": [{}]}],
    }))
    classes = tmp_path / "classes.json"
    classes.write_text(json.dumps([{"nameIdx": 7}, {"nameIdx": 3},
                                   {"nameIdx": 7}]), encoding="utf-8")
    out = tmp_path / "input.txt"
    report = build(method, classes, out)
    text = out.read_text(encoding="utf-8")
    assert report["target_rvas"] == 1
    assert report["type_indexes"] == 2
    assert "TARGET|slot=0x100|wrapper-rva=0x100" in text
    assert "0x200" not in text
    assert text.index("TYPE|index=3") < text.index("TYPE|index=7")
