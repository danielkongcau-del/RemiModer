from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller_closure_consolidate import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_supersedes_closed_api_gap_without_claiming_live_invocation(tmp_path: Path) -> None:
    role = {"summary": {"wrapper_observed": 4, "wrapper_total": 5,
        "native_implementation_observed": 0, "native_implementation_total": 5}}
    animator = {"checks": {"all_logical_edges_static_verified": True,
        "logical_edge_count": 17, "catalog_anchored_edge_count": 1}}
    acceptance = {"accepted": True, "game_runtime_verified": True,
                  "points": [{"status": "OBSERVED_LOSSLESS"}] * 13}
    api = {"scope": {"selectedEncryptedApiTargetsClosed": True,
        "selectedBridgeInvocationAbiClosed": True}, "invoke": {"unitySlotRva": 1,
        "gameTargetRva": 2, "invokerRva": 3, "bridgeCodeRva": 4,
        "argumentRegisters": ["RCX", "RDX", "R8"], "liveInvocationObserved": False}}
    callers = {"summary": {"unresolved_rows": 12}}
    occurrence = {"checks": {"scanned_occurrence_count": 1, "ok": True},
                  "occurrences": [{"ability": "AirCombat"}]}
    dispatch = {"checks": {"ok": True}, "classifications": [
        {"method": "HCB", "derived_role": "wrapper"},
        {"method": "BHCI", "derived_role": "nativeImplementation"}]}
    result = run(_write(tmp_path / "role.json", role), _write(tmp_path / "acceptance.json", acceptance),
                 _write(tmp_path / "anim.json", animator), _write(tmp_path / "api.json", api),
                 _write(tmp_path / "callers.json", callers), _write(tmp_path / "occ.json", occurrence),
                 _write(tmp_path / "dispatch.json", dispatch), tmp_path / "out")
    assert any("final target" in row["statement"] for row in result["superseded_gap_statements"])
    assert any("live selected Unity bridge" in row["claim"] for row in result["runtime_open"])
    assert result["runtime_required_now"] is False

    frontier = {"schema": "uc.entry-evidence-acceptance.v2", "accepted": False,
                "points": [{"point": "hot", "status": "UNKNOWN"},
                           {"point": "covered", "status": "OBSERVED"}]}
    next_plan = {"schema": "uc.capture-plan.v2", "plan_id": "next", "plan_revision": 2,
                 "points": [{"id": "hot", "retention": {
                     "mode": "first_per_entry_return_address", "max_keys": 16}}]}
    updated = run(tmp_path / "role.json", tmp_path / "acceptance.json", tmp_path / "anim.json",
                  tmp_path / "api.json", tmp_path / "callers.json", tmp_path / "occ.json",
                  tmp_path / "dispatch.json", tmp_path / "out2",
                  _write(tmp_path / "frontier.json", frontier),
                  _write(tmp_path / "next.json", next_plan))
    assert updated["runtime_required_now"] is True
    assert updated["next_capture"]["aggregate_caller_retention_points"] == ["hot"]
    assert "1 lossy points" in updated["runtime_observation_state"]["global_acceptance_reason"]


def test_rejects_unclosed_bridge_abi(tmp_path: Path) -> None:
    role = {"summary": {"wrapper_observed": 0, "wrapper_total": 0,
        "native_implementation_observed": 0, "native_implementation_total": 0}}
    animator = {"checks": {"all_logical_edges_static_verified": True}}
    acceptance = {"accepted": True, "game_runtime_verified": True, "points": []}
    api = {"scope": {"selectedEncryptedApiTargetsClosed": True,
        "selectedBridgeInvocationAbiClosed": False}}
    callers = {"summary": {"unresolved_rows": 0}}
    occurrence = {"checks": {"scanned_occurrence_count": 1, "ok": True},
                  "occurrences": [{}]}
    dispatch = {"checks": {"ok": True}, "classifications": []}
    try:
        run(_write(tmp_path / "role.json", role), _write(tmp_path / "acceptance.json", acceptance),
            _write(tmp_path / "anim.json", animator), _write(tmp_path / "api.json", api),
            _write(tmp_path / "callers.json", callers), _write(tmp_path / "occ.json", occurrence),
            _write(tmp_path / "dispatch.json", dispatch), tmp_path / "out")
    except ValueError as error:
        assert "bridge invocation ABI" in str(error)
    else:
        raise AssertionError("expected ValueError")
