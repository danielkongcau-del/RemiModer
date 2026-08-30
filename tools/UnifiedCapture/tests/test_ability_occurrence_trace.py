from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ability_occurrence_trace import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_resolves_inventory_pointer_and_scans_independently(tmp_path: Path) -> None:
    inventory = {"nativeTypeLedger": [{"serializedType": "Action", "occurrences": 1,
        "identityEvidenceKind": "fixture", "positions": [{"ability": "Ability",
            "jsonPointer": "/DefaultModifier/OnAdded/1"}], "nativeIdentityAndDispatch": {}}]}
    abilities = tmp_path / "abilities"
    abilities.mkdir()
    _write(abilities / "Ability.json", {"AbilityName": "Ability", "DefaultModifier": {
        "OnAdded": [{"$type": "Other"}, {"$type": "Action", "Value": 7}]}})
    result = run(_write(tmp_path / "inventory.json", inventory), abilities, "Action", tmp_path / "out")
    assert result["checks"]["all_declared_positions_resolved"] is True
    assert result["occurrences"][0]["parent_pointer"] == "/DefaultModifier/OnAdded"
    assert result["occurrences"][0]["node"]["Value"] == 7


def test_rejects_extra_untracked_occurrence(tmp_path: Path) -> None:
    inventory = {"nativeTypeLedger": [{"serializedType": "Action", "occurrences": 1,
        "positions": [{"ability": "Ability", "jsonPointer": "/Items/0"}],
        "nativeIdentityAndDispatch": {}}]}
    abilities = tmp_path / "abilities"
    abilities.mkdir()
    _write(abilities / "Ability.json", {"AbilityName": "Ability",
        "Items": [{"$type": "Action"}, {"$type": "Action"}]})
    try:
        run(_write(tmp_path / "inventory.json", inventory), abilities, "Action", tmp_path / "out")
    except ValueError as error:
        assert "checks failed" in str(error)
    else:
        raise AssertionError("expected ValueError")
