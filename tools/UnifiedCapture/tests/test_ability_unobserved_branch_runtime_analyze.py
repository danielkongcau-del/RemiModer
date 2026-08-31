from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_branch_runtime_analyze import summarize_events


def _contract(branch: str = "je", required: str = "FALLTHROUGH") -> dict:
    return {"physical_predicate_rva": 0x100,
            "represented_source_points": ["source/entry"],
            "logical_contracts": [{
                "predicate_instruction": {"mnemonic": "test"},
                "raw_tested_value": {"read_id": "tested-register"},
                "required_branch_outcome_for_original_site": required,
                "zero_branch_mnemonic": branch,
            }]}


def _event(value: int, control: int | None = None) -> tuple[dict, bytes]:
    reads = [{"id": "tested-register", "status": 1, "value": value}]
    if control is not None:
        reads.append({"id": "exact-field-C-F", "status": 1, "value": control})
    return ({"point": "AbilityBranchInput.Predicate@0x100/entry",
             "qpc": 15, "reads": reads}, b"")


def test_zero_predicate_outcome_and_control_consistency() -> None:
    result = summarize_events(
        [_event(4, 4), _event(0, 1)], contracts=[_contract()],
        windows=[{"id": "action", "begin_qpc_exclusive": 10,
                  "end_qpc_exclusive": 20}])
    row = result["predicate_sites"][0]
    assert row["required_path_admitted_events"] == 1
    assert row["required_path_rejected_events"] == 1
    assert row["control_consistency"]["matches"] == 1
    assert row["control_consistency"]["mismatches"] == 1
    assert row["checkpoint_windows"] == {"action": 2}


def test_taken_je_requires_zero() -> None:
    result = summarize_events([_event(0)], contracts=[_contract(required="TAKEN")],
                              windows=[])
    assert result["predicate_sites"][0]["required_path_admitted_events"] == 1


def test_fallthrough_jne_requires_zero() -> None:
    result = summarize_events([_event(0)], contracts=[_contract(branch="jne")],
                              windows=[])
    assert result["predicate_sites"][0]["required_path_admitted_events"] == 1
