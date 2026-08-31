from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_branch_ledger import (
    _callsite_path_status, _gating_branches, _register_family,
    _outcome_sensitive_branches,
)


def _ins(rva: int, size: int, mnemonic: str, target: int | None = None) -> dict:
    return {"rva": rva, "size": size, "mnemonic": mnemonic,
            "operands": f"{target:#x}" if target is not None else "",
            "bytes": "00", "groups": ["jump"] if mnemonic.startswith("j") else [],
            "direct_target_rva": target}


def test_dominating_one_outcome_branch_is_exact_gate() -> None:
    rows = [_ins(0, 2, "je", 6), _ins(2, 2, "mov"), _ins(4, 2, "jmp", 10),
            _ins(6, 2, "mov"), _ins(8, 2, "call"), _ins(10, 1, "ret")]
    gates = _gating_branches(rows, 0, 11, 8)
    assert [(row["branch_rva"], row["required_outcome"]) for row in gates] == [(0, "TAKEN")]


def test_branch_whose_both_outcomes_reach_site_is_not_gate() -> None:
    rows = [_ins(0, 2, "je", 4), _ins(2, 2, "jmp", 6),
            _ins(4, 2, "mov"), _ins(6, 2, "call"), _ins(8, 1, "ret")]
    assert _gating_branches(rows, 0, 9, 6) == []


def test_register_family_matches_jump_table_index_widths() -> None:
    assert _register_family("rax") == _register_family("eax")
    assert _register_family("r15") == _register_family("r15d")
    assert _register_family("rax") != _register_family("rcx")


def test_mandatory_callsite_dominates_all_mechanical_exits() -> None:
    rows = [_ins(0, 2, "je", 4), _ins(2, 2, "jmp", 6),
            _ins(4, 2, "mov"), _ins(6, 2, "call"), _ins(8, 1, "ret")]
    result = _callsite_path_status(rows, 0, 9, 6, {})
    assert result["status"] == "CALLSITE_MANDATORY_IN_COMPLETE_MECHANICAL_CFG"
    assert result["callsite_dominates_all_exits"] is True


def test_non_dominating_outcome_sensitive_branch_is_preserved() -> None:
    rows = [_ins(0, 2, "je", 8), _ins(2, 2, "je", 8),
            _ins(4, 2, "jmp", 10), _ins(6, 2, "mov"),
            _ins(8, 2, "call"), _ins(10, 1, "ret")]
    assert _gating_branches(rows, 0, 11, 8) == []
    sensitive = _outcome_sensitive_branches(rows, 0, 11, 8)
    assert any(row["branch_rva"] == 2 and row["required_outcome"] == "TAKEN"
               for row in sensitive)
