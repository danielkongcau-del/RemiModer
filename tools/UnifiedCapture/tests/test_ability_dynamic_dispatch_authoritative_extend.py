from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_dynamic_dispatch_authoritative_extend import (
    effect_index_catalog, extend, labeled_runtime_catalog,
)


def test_exact_harvests_extend_only_matching_rvas(tmp_path: Path) -> None:
    labeled = tmp_path / "labeled.txt"
    labeled.write_text(
        "CLASS|label=field+90|name=Dictionary`2|token=0x20005f1\n"
        "ARG|label=field+90|index=0|name=String|token=0x200013f\n"
        "METHOD|label=field+90|index=3|name=.ctor|rva=0x100\n",
        encoding="utf-8")
    effect = tmp_path / "effect.txt"
    effect.write_text(
        "hit=1 type=2 ordinal=3 token=0x2000001 namespace=<none> "
        "class=NativeClass method-index=4 method=Run method-info=00000001 "
        "code-rva=0x200 delta=0\n", encoding="utf-8")
    catalog = labeled_runtime_catalog(labeled)
    catalog.update(effect_index_catalog(effect))
    base = {
        "schema": "uc.ability-dynamic-dispatch-method-join.v1",
        "targets": [
            {"target_rva": 0x100, "method_candidates": []},
            {"target_rva": 0x200, "method_candidates": []},
            {"target_rva": 0x300, "method_candidates": []},
        ],
        "observed_class_target_pairs": [{
            "observed_class_name": "ObservedClass",
            "target": {"classification": "GAME_MODULE_RVA", "rva": 0x200},
            "method_candidates": [],
        }],
    }
    result = extend(base, catalog)
    assert result["summary"]["newly_catalogued_method_targets"] == 2
    assert result["summary"]["uncatalogued_method_targets"] == 1
    assert result["targets"][0]["method_candidates"][0]["declaring_class"] == "Dictionary`2"
    assert result["targets"][1]["method_candidates"][0]["method_name"] == "Run"
    pair = result["observed_class_target_pairs"][0]
    assert pair["observed_class_name"] == "ObservedClass"
    assert pair["method_candidates"][0]["declaring_class"] == "NativeClass"
