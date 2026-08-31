from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_external_target_body_ledger import (
    _instruction_shape, _mechanical_body_class,
)


def _ins(mnemonic: str, operands: str = "", groups: list[str] | None = None,
         target: int | None = None) -> dict:
    return {
        "mnemonic": mnemonic,
        "operands": operands,
        "groups": groups or [],
        "direct_target_rva": target,
    }


def test_call_then_trap_shape_is_mechanical_not_semantic() -> None:
    rows = [
        _ins("sub", "rsp, 0x28"),
        _ins("call", "0x180001000", ["call"], 0x1000),
        _ins("int3"),
    ]
    assert _mechanical_body_class(rows, True) == "DIRECT_CALL_THEN_TRAP_STUB"
    assert _mechanical_body_class(rows, False) == "INCOMPLETE_LINEAR_DECODE"


def test_body_classes_do_not_invent_names() -> None:
    assert _mechanical_body_class([_ins("ret")], True) == "CALL_FREE_BODY"
    assert _mechanical_body_class([
        _ins("call", "rax", ["call"]), _ins("ret")], True) == "MULTI_CALL_BODY"
    assert _mechanical_body_class([
        _ins("call", "0x180002000", ["call"], 0x2000), _ins("ret")], True
    ) == "SINGLE_DIRECT_CALL_BODY"


def test_instruction_shape_separates_local_and_external_direct_targets() -> None:
    assert _instruction_shape(
        _ins("call", "0x180001010", ["call"], 0x1010), 0x1000, 0x1100
    ) == "call <local-direct-target>"
    assert _instruction_shape(
        _ins("call", "0x180002000", ["call"], 0x2000), 0x1000, 0x1100
    ) == "call <external-direct-target>"
    assert _instruction_shape(
        _ins("mov", "rax, qword ptr [rip - 0x20]"), 0x1000, 0x1100
    ) == "mov rax, qword ptr [rip+disp]"
