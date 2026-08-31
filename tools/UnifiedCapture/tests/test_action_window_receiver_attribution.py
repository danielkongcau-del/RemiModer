from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from action_window_receiver_attribution import build
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_direct_join_and_same_address_are_not_conflated(tmp_path: Path) -> None:
    calls = [{"receiver": 10, "count": 2, "operation": "SetIntegerID",
              "parameter_id": 1, "raw_value_gpr": 3}]
    windows = [
        {"ordinal": 1, "from": "A", "to": "B", "label": "A->B",
         "begin_qpc_exclusive": 1, "end_qpc_exclusive": 2, "complete": True,
         "lost_events": 0, "event_count": 2, "animator_stage_object_counts": [],
         "selected_parameter_calls": calls},
        {"ordinal": 2, "from": "B", "to": "C", "label": "B->C",
         "begin_qpc_exclusive": 2, "end_qpc_exclusive": 3, "complete": True,
         "lost_events": 0, "event_count": 2, "animator_stage_object_counts": [],
         "selected_parameter_calls": calls},
    ]
    analysis = {"session_id": "s", "generation": 1,
        "integrity": {"store_clean": True, "lost_events": 0, "manifest_errors": []},
        "summary": {"stored_events": 4}, "action_windows": windows,
        "task_consumer_adjacency": [{"interval": "A->B", "receiver": 10,
            "same_thread_consecutive_stored_events": True}]}
    identity = {"session_id": "s", "generation": 1,
        "identity_chain": {"animator_receiver_candidate": {"address": 10}}}
    build(_write(tmp_path / "analysis.json", analysis),
          _write(tmp_path / "identity.json", identity), tmp_path / "out")
    import json
    artifact = json.loads((tmp_path / "out/action-window-receiver-attribution.json").read_text())
    assert artifact["windows"][0]["attribution_level"] == "DIRECT_REMIELLE_TASK_TO_CONSUMER_EVENTS"
    assert artifact["windows"][1]["attribution_level"] == "SAME_ADDRESS_RECEIVER_ACTIVITY_ONLY"
    assert artifact["windows"][1]["negative_claim_allowed"] is False


def test_rejects_lossy_window(tmp_path: Path) -> None:
    analysis = {"session_id": "s", "generation": 1,
        "integrity": {"store_clean": True, "lost_events": 0, "manifest_errors": []},
        "summary": {"stored_events": 0}, "task_consumer_adjacency": [],
        "action_windows": [{"complete": True, "lost_events": 1}]}
    identity = {"session_id": "s", "generation": 1,
        "identity_chain": {"animator_receiver_candidate": {"address": 10}}}
    try:
        build(_write(tmp_path / "analysis.json", analysis),
              _write(tmp_path / "identity.json", identity), tmp_path / "out")
    except ValueError as error:
        assert "complete and lossless" in str(error)
    else:
        raise AssertionError("expected ValueError")
