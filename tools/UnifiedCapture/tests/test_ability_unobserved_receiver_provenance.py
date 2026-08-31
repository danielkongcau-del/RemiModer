from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_receiver_provenance import (
    ReachingDefinitionAnalyzer, _target_origin, _vtable_contract)


def _row(rva: int, mnemonic: str, operands: str, *, size: int = 3,
         writes=(), groups=(), target=None):
    return {"rva": rva, "size": size, "mnemonic": mnemonic,
            "operands": operands, "regs_write": list(writes),
            "regs_read": [], "groups": list(groups),
            "direct_target_rva": target, "bytes": ""}


def test_prologue_this_alias_produces_exact_vtable_slot() -> None:
    rows = [
        _row(0x100, "mov", "rdi, rcx", writes=("rdi",)),
        _row(0x103, "mov", "rax, qword ptr [rdi]", writes=("rax",)),
        _row(0x106, "call", "qword ptr [rax + 0x118]", size=6,
             writes=("rsp",), groups=("call",)),
    ]
    analyzer = ReachingDefinitionAnalyzer(rows, 0x100, 0x10C, "Executor", {})
    target = _target_origin(analyzer, rows[-1])
    endpoint = _vtable_contract(target)
    assert endpoint is not None
    assert endpoint["vtable_slot"] == 9
    assert endpoint["receiver_provenance"] == {
        "kind": "ENTRY_THIS", "register": "rcx", "class": "Executor"}
    assert endpoint["receiver_provenance_exact"] is True


def test_register_target_vtable_shape_is_reclassified() -> None:
    rows = [
        _row(0x200, "mov", "rax, qword ptr [rcx]", writes=("rax",)),
        _row(0x203, "mov", "rax, qword ptr [rax + 0x100]", size=7,
             writes=("rax",)),
        _row(0x20A, "call", "rax", size=2, writes=("rsp",), groups=("call",)),
    ]
    analyzer = ReachingDefinitionAnalyzer(rows, 0x200, 0x20C, "Executor", {})
    endpoint = _vtable_contract(_target_origin(analyzer, rows[-1]))
    assert endpoint is not None
    assert endpoint["vtable_slot"] == 6
    assert endpoint["concrete_runtime_class_proven"] is True


def test_cfg_merge_preserves_finite_exact_receiver_alternatives() -> None:
    rows = [
        _row(0x300, "test", "rax, rax", size=2, writes=("rflags",)),
        _row(0x302, "je", "0x140000309", size=2, groups=("jump",), target=0x309),
        _row(0x304, "mov", "rdi, rcx", writes=("rdi",)),
        _row(0x307, "jmp", "0x14000030c", size=2, groups=("jump",), target=0x30C),
        _row(0x309, "mov", "rdi, rdx", writes=("rdi",)),
        _row(0x30C, "mov", "rax, qword ptr [rdi]", writes=("rax",)),
        _row(0x30F, "call", "qword ptr [rax + 0x110]", size=6,
             writes=("rsp",), groups=("call",)),
    ]
    analyzer = ReachingDefinitionAnalyzer(rows, 0x300, 0x315, "Executor", {})
    endpoint = _vtable_contract(_target_origin(analyzer, rows[-1]))
    assert endpoint is not None
    assert endpoint["receiver_provenance"]["kind"] == "BOUNDED_ALTERNATIVES"
    assert endpoint["receiver_provenance_exact"] is True


def test_exact_harvested_field_materializes_receiver_class() -> None:
    rows = [
        _row(0x400, "mov", "rdi, qword ptr [rcx + 0x50]", size=4,
             writes=("rdi",)),
        _row(0x404, "mov", "rax, qword ptr [rdi]", writes=("rax",)),
        _row(0x407, "call", "qword ptr [rax + 0xf0]", size=6,
             writes=("rsp",), groups=("call",)),
    ]
    fields = {("Executor", 0x50): [{
        "class": "Executor", "field": "Target", "materializedClass": "Entity",
        "offset": "0x50", "token": "0x1"}]}
    analyzer = ReachingDefinitionAnalyzer(rows, 0x400, 0x40D, "Executor", fields)
    endpoint = _vtable_contract(_target_origin(analyzer, rows[-1]))
    assert endpoint is not None
    assert endpoint["vtable_slot"] == 4
    assert endpoint["receiver_provenance"]["kind"] == "EXACT_FIELD_LOAD"
    assert endpoint["receiver_provenance"]["class"] == "Entity"


def test_stack_receiver_is_normalized_to_entry_stack_offset() -> None:
    rows = [
        _row(0x500, "push", "rbx", size=1, writes=("rsp",)),
        _row(0x501, "sub", "rsp, 0x20", size=4, writes=("rsp",)),
        _row(0x505, "mov", "rsi, qword ptr [rsp + 0x50]", size=5,
             writes=("rsi",)),
        _row(0x50A, "mov", "rax, qword ptr [rsi]", writes=("rax",)),
        _row(0x50D, "call", "qword ptr [rax + 0x110]", size=6,
             writes=("rsp",), groups=("call",)),
    ]
    analyzer = ReachingDefinitionAnalyzer(rows, 0x500, 0x513, "Executor", {})
    endpoint = _vtable_contract(_target_origin(analyzer, rows[-1]))
    assert endpoint is not None
    assert endpoint["receiver_provenance"]["kind"] == "ENTRY_STACK_LOAD"
    assert endpoint["receiver_provenance"]["stack_entry_offset"] == 0x28
    assert endpoint["receiver_provenance_exact"] is True
