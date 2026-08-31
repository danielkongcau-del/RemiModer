from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_trace_conformance import classify_window


def _window(**updates) -> dict:
    row = {
        "user_annotated_interval": "NORMAL_CHAIN->DODGE_ONLY",
        "complete": True, "lost_events": 0,
        "direct_same_thread_consecutive_task_consumer_events": 0,
        "same_address_receiver_selected_calls": 0,
        "attribution_level": "NO_JOINED_RECEIVER_ACTIVITY",
    }
    row.update(updates)
    return row


def test_only_direct_causal_witness_is_a_match() -> None:
    verdict, _ = classify_window(_window(
        direct_same_thread_consecutive_task_consumer_events=2,
        attribution_level="DIRECT_REMIELLE_TASK_TO_CONSUMER_EVENTS"))
    assert verdict == "MATCH"


def test_same_address_and_zero_traffic_remain_unknown() -> None:
    verdict, _ = classify_window(_window(
        same_address_receiver_selected_calls=4,
        attribution_level="SAME_ADDRESS_RECEIVER_ACTIVITY_ONLY"))
    assert verdict == "UNKNOWN"
    verdict, _ = classify_window(_window())
    assert verdict == "UNKNOWN"


def test_integrity_failure_is_mismatch_and_setup_is_not_applicable() -> None:
    verdict, _ = classify_window(_window(lost_events=1))
    assert verdict == "MISMATCH"
    verdict, _ = classify_window(
        _window(user_annotated_interval="ENTRY_UNIT_ARMED->PRE_TRIAL_ARMED"))
    assert verdict == "NOT_APPLICABLE"
