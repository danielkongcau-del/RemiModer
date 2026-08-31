from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_dynamic_dispatch_method_join import build_catalog, join


def test_exact_rva_join_preserves_runtime_class_as_separate_evidence() -> None:
    truth = {"schema": "zzz.remielle.origin-controller-execution-truth.v1",
             "nativeTypeTable": [{"semanticType": "BulletMixin", "configClass": "CFG",
                                  "role": "mixin", "dispatch": {"operationalMethods": [
                                      {"rva": 0x123, "name": "NativeMethod",
                                       "signature": ["return=Void"]}]}}]}
    catalog = build_catalog(truth, [])
    runtime = {"schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
               "dynamic_sites": [{"point": "P", "targets": [
                   {"classification": "GAME_MODULE_RVA", "rva": 0x123}],
                   "class_target_pairs": [{"class_name": "RuntimeSubclass",
                                            "target": {"classification": "GAME_MODULE_RVA",
                                                       "rva": 0x123}, "count": 7}]}]}
    result = join(runtime, catalog)
    pair = result["observed_class_target_pairs"][0]
    assert pair["observed_class_name"] == "RuntimeSubclass"
    assert pair["method_candidates"][0]["declaring_semantic_type"] == "BulletMixin"
    assert result["summary"]["exact_catalogued_method_targets"] == 1


def test_uncatalogued_target_remains_explicitly_unresolved() -> None:
    runtime = {"schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
               "dynamic_sites": [{"point": "P", "targets": [
                   {"classification": "GAME_MODULE_RVA", "rva": 0x999}],
                   "class_target_pairs": []}]}
    result = join(runtime, {})
    assert result["targets"][0]["catalog_status"] == "NO_CATALOG_MATCH"
    assert result["summary"]["uncatalogued_method_targets"] == 1
