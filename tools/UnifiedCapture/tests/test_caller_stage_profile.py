from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caller_stage_profile import build


def _interval(label, address, callbacks):
    return {"from": {"label": label}, "to": {"label": "next"},
        "admission_window_drops": 0, "unattributed_storage_loss_events": 0,
        "points": [{"point": "p", "integrity":
            "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS",
            "caller_key_deltas": [{"entry_return_address": address,
                                    "callbacks": callbacks}]}]}


def test_action_exclusivity_ignores_pre_action_counts():
    caller = {"return_address": 0x5100, "module": "unity", "return_rva": 0x100,
              "callsite_rva": 0xFE, "callsite_status": "resolved",
              "caller_runtime_function": {"begin_rva": 0x80}}
    acceptance = {"points": [{"point": "p", "runtime_caller_evidence": [caller]}]}
    deltas = {"intervals": [_interval("armed", 0x5100, 5),
                             _interval("BASELINE", 0x5100, 9),
                             _interval("TASK", 0x5100, 0)]}
    joined = {"caller_evidence": [{"callee_point": "p", "callsite_rva": 0xFE,
        "caller_runtime_function": {"begin_rva": 0x80}, "static_match": True,
        "logical_owner": {"logical_root_rva": 0x80}, "catalog_matches": []}]}
    result = build(acceptance, deltas, joined)
    row = result["callers"][0]
    assert row["counts_by_interval"] == {"PRE_ACTION": 5, "BASELINE": 9,
                                          "TASK": 0}
    assert row["exclusive_to_one_action_window"] is True
    assert row["dominant_action_label"] == "BASELINE"
    assert row["dominant_action_share_ppm"] == 1_000_000
    assert row["static_match"] is True


def test_integrity_gap_is_rejected():
    delta = _interval("armed", 0x1, 1)
    delta["admission_window_drops"] = 1
    try:
        build({"points": []}, {"intervals": [delta]}, {"caller_evidence": []})
    except ValueError as error:
        assert "lossless" in str(error)
    else:
        raise AssertionError("expected ValueError")
