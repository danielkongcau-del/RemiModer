"""Close the ordinary/enhanced special definition from authoritative game assets.

Runtime execution coverage is deliberately reported separately.  This tool
does not infer an input binding or claim that either state executed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _set_parameter_action(rows: list[dict[str, Any]], value: int) -> dict[str, Any]:
    matches = [row for row in rows
               if row.get("$type") == "SetAnimCtrlerParamAction"
               and row.get("ParamName") == "Int_BranchIndex"
               and row.get("ParamType") == 3 and row.get("IntVal") == value
               and row.get("Target") == "Self"]
    if len(matches) != 1:
        raise ValueError(f"expected one Int_BranchIndex={value} action")
    return matches[0]


def build(ability_path: Path, controller_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    ability = _load(ability_path)
    controller = _load(controller_path)
    if ability.get("AbilityName") != "RemielleOrigin_SpecialSkill":
        raise ValueError("unexpected authoritative special ability")
    if controller.get("controllerName") != "Avatar_Female_Size02_RemielleOrigin_Controller":
        raise ValueError("unexpected authoritative controller")

    property_mixins = [row for row in ability.get("AbilityMixins", [])
                       if row.get("$type") == "ActionsOnPropertyChangeMixin"]
    candidates = []
    for mixin in property_mixins:
        for action in mixin.get("PropertyActions", []):
            if (action.get("PropertyType") == "CurSP"
                    and action.get("ReferMaxPropertyType") == "MaxSP"
                    and action.get("IsUsePercentage") is False):
                candidates.append(action)
    if len(candidates) != 1:
        raise ValueError("expected one exact CurSP property action")
    ranges = candidates[0].get("ValueRangeActions", [])
    if len(ranges) != 2 or [row.get("Val") for row in ranges] != [60, 60]:
        raise ValueError("CurSP threshold rows differ from authoritative pair")
    low_to_value = _set_parameter_action(ranges[0].get("LowToValueActions", []), 1)
    value_to_low = _set_parameter_action(ranges[1].get("ValueToLowActions", []), 0)

    attach = [row for row in ability.get("AbilityMixins", [])
              if row.get("$type") == "AttachStateWithModifierMixin"]
    if len(attach) != 1:
        raise ValueError("expected one state-attachment mixin")
    attached = attach[0].get("ConfigList", [])
    attached_by_name = {row.get("AnimatorStateName"): row for row in attached}
    expected_states = ("Attack_Special", "Attack_ExSpecial")
    if set(attached_by_name) != set(expected_states):
        raise ValueError("special state attachment pair differs")
    for name in expected_states:
        row = attached_by_name[name]
        if (row.get("FrameCountLow") != 0 or row.get("MaxFrameCountHigh") is not True
                or row.get("ModifierNameList") != ["SpecialStateGuardModifier"]):
            raise ValueError(f"{name}: state attachment contract differs")

    parameters = [row for row in controller.get("parameters", [])
                  if row.get("name") == "Int_BranchIndex"]
    if len(parameters) != 1 or parameters[0].get("typeStr") != "int" or parameters[0].get(
            "type") != 3:
        raise ValueError("controller Int_BranchIndex declaration differs")
    base_layers = [row for row in controller.get("layers", [])
                   if row.get("name") == "Base Layer"]
    if len(base_layers) != 1:
        raise ValueError("expected one authoritative Base Layer")
    states = {row.get("name"): row for row in base_layers[0].get("states", [])}
    state_rows = []
    for name in (*expected_states, "Attack_Special_End", "Attack_ExSpecial_End"):
        row = states.get(name)
        if row is None or not row.get("fullPath", "").endswith(name):
            raise ValueError(f"controller state absent: {name}")
        state_rows.append({
            "name": name, "index": int(row["index"]), "name_hash": row["nameHash"],
            "full_path": row["fullPath"], "outgoing_transitions": len(row["transitions"]),
        })
    clip_names = {row.get("name") for row in controller.get("animationClips", [])}
    expected_clips = [
        f"Avatar_Female_Size02_Remielle_Origin_Ani_{suffix}"
        for suffix in ("Attack_Special", "Attack_ExSpecial",
                       "Attack_Special_End", "Attack_ExSpecial_End")]
    missing_clips = sorted(set(expected_clips) - clip_names)
    if missing_clips:
        raise ValueError(f"authoritative special clips absent: {missing_clips}")

    sources = {"special_ability": _source(ability_path),
               "animator_controller": _source(controller_path)}
    artifact = {
        "schema": "uc.ordinary-special-static-closure.v1",
        "sources": sources,
        "property_threshold": {
            "property": "CurSP", "refer_max_property": "MaxSP",
            "is_percentage": False, "threshold": 60,
            "low_to_value_action": low_to_value,
            "value_to_low_action": value_to_low,
        },
        "animator_parameter": {
            "name": parameters[0]["name"], "id": int(parameters[0]["id"]),
            "type": int(parameters[0]["type"]), "type_string": parameters[0]["typeStr"],
        },
        "attached_states": [attached_by_name[name] for name in expected_states],
        "controller_states": state_rows,
        "animation_clips": expected_clips,
        "acceptance": {
            "ordinary_and_enhanced_definitions_present": True,
            "threshold_parameter_updates_present": True,
            "state_attachment_pair_present": True,
            "controller_state_and_end_state_pair_present": True,
            "animation_clip_pair_present": True,
            "structural_definition_closed": True,
            "runtime_execution_observed_by_this_artifact": False,
            "runtime_execution_required_for_definition_closure": False,
        },
        "limits": [
            "LowToValueActions and ValueToLowActions are preserved game field names; no additional direction semantics are invented",
            "the asset proves both definitions and their CurSP-driven branch parameter updates, not a live player input event",
            "controller state motion-set decoding is not used because the extracted controller already supplies an independent animation-clip table",
        ],
    }
    out.mkdir(parents=True)
    artifact_path = out / "ordinary-special-static-closure.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ordinary-special-static-closure-report.v1",
        "artifact": _source(artifact_path),
        "structural_definition_closed": True,
        "runtime_execution_required_for_definition_closure": False,
        "controller_states": len(state_rows), "animation_clips": len(expected_clips),
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ability", type=Path, required=True)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.ability.resolve(), args.controller.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ordinary_special_static_closure", error, {
            "ability": str(args.ability), "controller": str(args.controller)})
        raise


if __name__ == "__main__":
    run_main(main)
