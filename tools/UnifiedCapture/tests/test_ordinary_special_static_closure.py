from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ordinary_special_static_closure import build


def _write(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_static_special_pair_closes_without_runtime_execution(tmp_path: Path) -> None:
    ability = {
        "AbilityName": "RemielleOrigin_SpecialSkill",
        "AbilityMixins": [
            {"$type": "ActionsOnPropertyChangeMixin", "PropertyActions": [{
                "PropertyType": "CurSP", "ReferMaxPropertyType": "MaxSP",
                "IsUsePercentage": False, "ValueRangeActions": [
                    {"Val": 60, "LowToValueActions": [{
                        "$type": "SetAnimCtrlerParamAction", "ParamName": "Int_BranchIndex",
                        "ParamType": 3, "IntVal": 1, "Target": "Self"}]},
                    {"Val": 60, "ValueToLowActions": [{
                        "$type": "SetAnimCtrlerParamAction", "ParamName": "Int_BranchIndex",
                        "ParamType": 3, "IntVal": 0, "Target": "Self"}]},
                ]}]},
            {"$type": "AttachStateWithModifierMixin", "ConfigList": [
                {"AnimatorStateName": name, "FrameCountLow": 0,
                 "MaxFrameCountHigh": True,
                 "ModifierNameList": ["SpecialStateGuardModifier"]}
                for name in ("Attack_Special", "Attack_ExSpecial")]},
        ],
    }
    names = ("Attack_Special", "Attack_ExSpecial",
             "Attack_Special_End", "Attack_ExSpecial_End")
    controller = {
        "controllerName": "Avatar_Female_Size02_RemielleOrigin_Controller",
        "parameters": [{"name": "Int_BranchIndex", "id": 7,
                        "type": 3, "typeStr": "int"}],
        "layers": [{"name": "Base Layer", "states": [
            {"name": name, "index": index, "nameHash": hex(index + 1),
             "fullPath": "Base." + name, "transitions": [{}]}
            for index, name in enumerate(names)]}],
        "animationClips": [{"name": "Avatar_Female_Size02_Remielle_Origin_Ani_" + name}
                           for name in names],
    }
    report = build(_write(tmp_path / "ability.json", ability),
                   _write(tmp_path / "controller.json", controller),
                   tmp_path / "out")
    artifact = json.loads(Path(report["artifact"]["path"]).read_text())
    assert report["structural_definition_closed"] is True
    assert artifact["property_threshold"]["threshold"] == 60
    assert artifact["acceptance"]["runtime_execution_required_for_definition_closure"] is False


def test_missing_ordinary_state_is_rejected(tmp_path: Path) -> None:
    # Use the complete fixture once, then remove the exact ordinary state.
    with __import__("pytest").raises(ValueError):
        build(_write(tmp_path / "ability.json", {
                  "AbilityName": "RemielleOrigin_SpecialSkill", "AbilityMixins": []}),
              _write(tmp_path / "controller.json", {
                  "controllerName": "Avatar_Female_Size02_RemielleOrigin_Controller",
                  "parameters": [], "layers": [{"states": []}],
                  "animationClips": []}), tmp_path / "out")
