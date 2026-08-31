from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_executor_arena_slot_join import _class_catalog, _preserved_game_base


def test_preserved_game_base_requires_explicit_layout_evidence(tmp_path: Path) -> None:
    source = tmp_path / "layout.md"
    source.write_text("GameAssembly 基址 0x7FF8DA050000。\n", encoding="utf-8")
    assert _preserved_game_base(source) == 0x7FF8DA050000


def test_class_catalog_keys_by_token_and_name() -> None:
    catalog = _class_catalog([{
        "name": "Transform", "ns": "UnityEngine", "token": "0x2000179",
        "nameIdx": 5417, "methods": 124, "vtSlots": 5, "parentName": "Component",
    }])
    assert catalog[(0x2000179, "Transform")][0]["methods"] == 124
    assert catalog[(0x2000179, "Transform")][0]["nameIdx"] == 5417
    assert (0x2000179, "Component") not in catalog
