from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_static_relevance import build


def test_unobserved_sites_join_asset_relevance_without_inventing_predicates(tmp_path: Path) -> None:
    runtime_path = tmp_path / "runtime.json"
    coverage_path = tmp_path / "coverage.json"
    runtime_path.write_text(json.dumps({
        "schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
        "session": {"cleanup": "STOPPED_CLEAN", "loss_events": 0, "storage_complete": True},
        "summary": {"unobserved_dynamic_probe_sites": 2},
        "dynamic_sites": [
            {"point": "a", "observation": "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION",
             "static_contract": {"physical_probe_rva": 1, "represented_callsites": [{
                 "site_rva": 2, "caller_type": "A", "caller_method": ".cctor",
                 "dispatch_form": "REGISTER_TARGET", "local_dataflow": {}}]}},
            {"point": "b", "observation": "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION",
             "static_contract": {"physical_probe_rva": 3, "represented_callsites": [{
                 "site_rva": 4, "caller_type": "B", "caller_method": "Run",
                 "dispatch_form": "OBJECT_OR_VTABLE_SLOT", "local_dataflow": {}}]}},
        ]}), encoding="utf-8")
    coverage_path.write_text(json.dumps({
        "schema": "uc.ability-executor-coverage-ledger.v1", "types": [
            {"serialized_type": "A", "occurrences": 2, "abilities": ["OriginA"],
             "inventory_pointer": "/0", "positions_complete": True},
            {"serialized_type": "B", "occurrences": 3, "abilities": ["OriginB"],
             "inventory_pointer": "/1", "positions_complete": True},
        ]}), encoding="utf-8")
    out = tmp_path / "out"
    report = build(runtime_path, coverage_path, out)
    assert report["summary"]["callsites_with_remielle_origin_asset_occurrences"] == 2
    assert report["summary"]["classification_counts"] == {
        "RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH": 1,
        "STATIC_INITIALIZER_TIMING_SITE": 1,
    }
