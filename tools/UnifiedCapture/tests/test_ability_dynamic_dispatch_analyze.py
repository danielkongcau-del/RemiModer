from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_dynamic_dispatch_analyze import (
    _address, _checkpoint_windows, summarize_events,
)


def _event(point: str, qpc: int, reads: list[dict]) -> tuple[dict, bytes]:
    blob = b"ActionTask\0" + b"\0" * 24
    return ({"point": point, "qpc": qpc, "reads": reads}, blob)


def test_address_classification_does_not_name_external_targets() -> None:
    assert _address(0, 0x1000, 0x1000)["classification"] == "NULL"
    assert _address(0x1234, 0x1000, 0x1000) == {
        "address": 0x1234, "classification": "GAME_MODULE_RVA", "rva": 0x234}
    assert _address(0x3000, 0x1000, 0x1000) == {
        "address": 0x3000, "classification": "EXTERNAL_ABSOLUTE_ADDRESS"}


def test_checkpoint_windows_use_only_conservative_interiors() -> None:
    windows = _checkpoint_windows([
        {"checkpoint_id": 1, "label": "A", "snapshot_begin_qpc": 8,
         "snapshot_end_qpc": 10},
        {"checkpoint_id": 2, "label": "B", "snapshot_begin_qpc": 20,
         "snapshot_end_qpc": 22},
    ])
    assert windows[0]["begin_qpc_exclusive"] == 10
    assert windows[0]["end_qpc_exclusive"] == 20


def test_summary_separates_target_class_and_observed_address_candidates() -> None:
    point = "AbilityDispatch.Dynamic@0x200/entry"
    reads = [
        {"id": "dispatch-target-0-200", "status": 1, "value": 0x1234,
         "offset": 0, "length": 8},
        {"id": "class-name-rax", "status": 1, "value": 10,
         "offset": 0, "length": 10},
        {"id": "object-rcx", "status": 1, "value": 0x9000,
         "offset": 16, "length": 8},
    ]
    result = summarize_events(
        [_event(point, 15, reads)], points=[point], module_base=0x1000,
        module_size=0x1000,
        windows=[{"id": "A->B", "begin_qpc_exclusive": 10,
                  "end_qpc_exclusive": 20}],
    )
    row = result["dynamic_sites"][0]
    assert row["targets"] == [{"address": 0x1234,
                                "classification": "GAME_MODULE_RVA",
                                "rva": 0x234, "count": 1}]
    assert row["class_names"] == [{"name": "ActionTask", "count": 1}]
    assert row["class_target_pairs"] == [{
        "class_name": "ActionTask",
        "target": {"address": 0x1234, "classification": "GAME_MODULE_RVA",
                   "rva": 0x234},
        "count": 1,
    }]
    assert row["observed_address_candidates"][0]["unique_addresses"] == 1
    assert row["action_windows"] == {"A->B": 1}


def test_zero_event_point_uses_bounded_not_observed_wording() -> None:
    point = "AbilityDispatch.Dynamic@0x300/entry"
    result = summarize_events([], points=[point], module_base=0x1000,
                              module_size=0x1000, windows=[])
    assert result["dynamic_sites"][0]["observation"] == (
        "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION")
