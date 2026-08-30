from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller_role_gap import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def _inventory() -> dict:
    rows = []
    names = ["HandleAnimatorZoneTagsAction", "ModifyEnterBattleStateAction",
             "SetAbilitySpecialAction", "SetTargetAbilitySpecialAction", "TriggerAbilityAction"]
    for index, name in enumerate(names):
        rows.append({"serializedType": name, "occurrences": 1, "positions": [{}],
            "nativeIdentityAndDispatch": {"occurrencesAcrossAll51Abilities": 1,
                "dispatch": {"wrapper": {"name": "HCBMKBDIHJB", "rva": 0x1000 + index},
                             "nativeImplementation": {"name": "BHCIJGGHECM", "rva": 0x2000 + index}}}})
    rows.append({"serializedType": "ApplyLogicMoveAction", "occurrences": 1, "positions": [{}],
                 "nativeIdentityAndDispatch": {"methods": [
                     {"name": "HCBMKBDIHJB", "rva": 0x3000},
                     {"name": "BHCIJGGHECM", "rva": 0x3001}]}})
    return {"nativeTypeLedger": rows}


def test_roles_do_not_turn_native_variant_into_gameplay_gap(tmp_path: Path) -> None:
    wrappers = ["HandleAnimatorZoneTagsAction", "SetAbilitySpecialAction",
                "SetTargetAbilitySpecialAction", "TriggerAbilityAction"]
    observed = [f"{name}.HCBMKBDIHJB/entry" for name in wrappers]
    observed += ["ApplyLogicMoveAction.HCBMKBDIHJB/entry",
                 "SetBoolParameter.OnStart@0x10/entry", "SetBoolParameter.OnUpdate@0x20/entry"]
    missing = [f"{name}.BHCIJGGHECM/entry" for name in wrappers]
    missing += ["ModifyEnterBattleStateAction.HCBMKBDIHJB/entry",
                "ModifyEnterBattleStateAction.BHCIJGGHECM/entry",
                "ApplyLogicMoveAction.BHCIJGGHECM/entry", "SetBoolParameter.OnReset@0x30/entry"]
    controller = {"lossless": True, "manifest_errors": [], "observed_points": observed,
                  "not_observed_in_covered_lossless_overall_window": missing}
    caller = {"summary": {"runtime_callsite_rows": 2, "source_identified_rows": 1}}
    result = run(_write(tmp_path / "controller.json", controller),
                 _write(tmp_path / "inventory.json", _inventory()),
                 _write(tmp_path / "caller.json", caller), tmp_path / "out")
    assert result["summary"]["wrapper_observed"] == 4
    assert result["summary"]["native_implementation_observed"] == 0
    assert result["gameplay_runtime_candidates"] == [{
        "point": "ModifyEnterBattleStateAction.HCBMKBDIHJB/entry",
        "serialized_type": "ModifyEnterBattleStateAction",
        "reason": "serialized action wrapper has asset occurrences but was not observed"}]
    apply = next(row for row in result["ability_action_entries"]
                 if row["serialized_type"] == "ApplyLogicMoveAction")
    assert apply["dispatch_role_status"] == "UNCLASSIFIED_BY_NATIVE_INVENTORY"


def test_rejects_non_lossless_controller_source(tmp_path: Path) -> None:
    controller = {"lossless": False, "manifest_errors": [], "observed_points": []}
    try:
        run(_write(tmp_path / "controller.json", controller),
            _write(tmp_path / "inventory.json", _inventory()),
            _write(tmp_path / "caller.json", {"summary": {}}), tmp_path / "out")
    except ValueError as error:
        assert "not lossless" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_accepts_checked_mechanical_dispatch_role_derivation(tmp_path: Path) -> None:
    controller = {"lossless": True, "manifest_errors": [],
        "observed_points": ["ApplyLogicMoveAction.HCBMKBDIHJB/entry"],
        "not_observed_in_covered_lossless_overall_window": [
            "ApplyLogicMoveAction.BHCIJGGHECM/entry"]}
    evidence = {"target_type": "ApplyLogicMoveAction",
        "checks": {"both_members_classified": True, "roles_are_distinct": True},
        "classifications": [
            {"method": "HCBMKBDIHJB", "derived_role": "wrapper"},
            {"method": "BHCIJGGHECM", "derived_role": "nativeImplementation"}]}
    result = run(_write(tmp_path / "controller.json", controller),
                 _write(tmp_path / "inventory.json", _inventory()),
                 _write(tmp_path / "caller.json", {"summary": {}}), tmp_path / "out",
                 [_write(tmp_path / "dispatch.json", evidence)])
    apply = next(row for row in result["ability_action_entries"]
                 if row["serialized_type"] == "ApplyLogicMoveAction")
    assert apply["dispatch_role_status"].startswith("MECHANICALLY_DERIVED")
    assert result["summary"]["wrapper_observed"] == 1
    assert result["summary"]["role_classified_action_types"] == 6
