from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from field_lifecycle_analyze import analyze_events, stable_intervals, _stream_summary_path


def _checkpoint_delta():
    return {"intervals": [{
        "from": {"label": "A", "snapshot_end_qpc": 10},
        "to": {"label": "B", "snapshot_begin_qpc": 20},
        "admission_window_drops": 0,
        "unattributed_storage_loss_events": 0,
        "points": [{"lost_events": 0,
                    "integrity": "LOSSLESS_COUNTER_DELTA_BETWEEN_BOUNDED_SNAPSHOTS"}],
    }]}


def _event(qpc, point, address, **values):
    reads = [{"id": "raw-rcx", "value": address, "status": 1}]
    reads.extend({"id": key, "value": value, "status": 1}
                 for key, value in values.items())
    return {"generation": 3, "qpc": qpc, "point": point, "reads": reads}


def test_same_address_task_phases_are_related_without_identity_upgrade():
    intervals = stable_intervals(_checkpoint_delta())
    result = analyze_events([
        _event(11, "SetBoolParameter.OnStart@0x1/entry", 0x100, field=7),
        _event(12, "SetBoolParameter.OnUpdate@0x2/entry", 0x100, field=8),
    ], intervals, 3)
    assert result["summary"]["parameter_task_address_candidates"] == 1
    assert result["summary"]["parameter_task_start_update_same_address"] == 1
    row = result["candidates"][0]
    assert row["observed_address"] == 0x100
    assert row["methods"] == {"OnStart": 1, "OnUpdate": 1}
    assert row["field_values"]["field"] == [7, 8]


def test_ecs_lifecycle_and_boundary_exclusion_are_explicit():
    intervals = stable_intervals(_checkpoint_delta())
    methods = (".ctor", "CreateFilters", "Start", "Update", "OnDestroy")
    events = [_event(11 + index, f"ODKPBBAJAEG.{name}@0x{index:x}/entry", 0x200)
              for index, name in enumerate(methods)]
    events.append(_event(20, "ODKPBBAJAEG.Update@0x9/entry", 0x200))
    result = analyze_events(events, intervals, 3)
    assert result["summary"]["ecs_complete_lifecycles"] == 1
    assert result["events_excluded_at_checkpoint_boundaries"] == 1
    assert result["candidates"][0]["stages"] == {"A->B": 5}


def test_incomplete_interval_is_not_lossless():
    delta = _checkpoint_delta()
    delta["intervals"][0]["admission_window_drops"] = 1
    assert stable_intervals(delta)[0]["complete"] is False


def test_streaming_summary_name_from_finalize_is_preferred(tmp_path: Path):
    legacy = tmp_path / "stream-summary.json"
    current = tmp_path / "streaming-summary.json"
    legacy.write_text("{}", encoding="utf-8")
    current.write_text("{}", encoding="utf-8")
    assert _stream_summary_path(tmp_path) == current
