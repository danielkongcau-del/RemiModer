from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_capture_frontier import parameter_subscriptions, selected_wrappers


def test_parameter_subscriptions_expand_trigger_reset_only() -> None:
    rows = parameter_subscriptions([
        {"name": "F", "id": 1, "typeStr": "float"},
        {"name": "I", "id": 2, "typeStr": "int"},
        {"name": "B", "id": 3, "typeStr": "type4"},
        {"name": "T", "id": 4, "typeStr": "bool/trigger"},
    ])
    assert {(row["method"], row["id"]) for row in rows} == {
        ("SetFloatID", 1), ("SetIntegerID", 2), ("SetBoolID", 3),
        ("SetTriggerID", 4), ("ResetTriggerID", 4),
    }


def test_selected_wrappers_exclude_aircombat_and_unobserved() -> None:
    role_gap = {"ability_action_entries": [
        {"serialized_type": "ModifyEnterBattleStateAction", "roles": {"wrapper": {
            "point": "ModifyEnterBattleStateAction.H/entry", "status": "OBSERVED_IN_LOSSLESS_COVERED_WINDOW"}}},
        {"serialized_type": "TriggerAbilityAction", "roles": {"wrapper": {
            "point": "TriggerAbilityAction.H/entry", "status": "OBSERVED_IN_LOSSLESS_COVERED_WINDOW"}}},
        {"serialized_type": "MissingAction", "roles": {"wrapper": {
            "point": "MissingAction.H/entry", "status": "NOT_OBSERVED_IN_COVERED_WINDOW"}}},
    ]}
    assert selected_wrappers(role_gap) == ["TriggerAbilityAction.H"]
