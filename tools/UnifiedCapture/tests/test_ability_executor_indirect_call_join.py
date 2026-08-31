from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_executor_indirect_call_join import (
    _classification, _nearest_linear_writer, _signed_rip_target, _stub_slot,
    _unresolved_slot_account,
)


class _Instruction:
    def __init__(self, mnemonic: str, op_str: str, size: int):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size


class _Disassembler:
    def __init__(self, instructions: list[_Instruction]):
        self.instructions = instructions

    def disasm(self, raw: bytes, address: int):
        return self.instructions


class _Pe:
    image_base = 0x180000000

    def __init__(self, instructions: list[_Instruction]):
        self.cs = _Disassembler(instructions)

    def bytes_at(self, rva: int, size: int) -> bytes:
        return b"\x90" * size


def test_signed_rip_target_uses_end_of_instruction() -> None:
    assert _signed_rip_target(0x1000, 6, "qword ptr [rip + 0x20]") == 0x1026
    assert _signed_rip_target(0x1000, 6, "qword ptr [rip - 0x20]") == 0xFE6
    assert _signed_rip_target(0x1000, 6, "qword ptr [rax + 0x20]") is None


def test_stub_slot_accepts_only_exact_generated_forms() -> None:
    direct = _Pe([_Instruction("jmp", "qword ptr [rip + 0x20]", 6)])
    assert _stub_slot(direct, 0x1000) == (0x1026, "RIP_MEMORY_JUMP")
    loaded = _Pe([_Instruction("mov", "rax, qword ptr [rip - 0x20]", 7),
                  _Instruction("jmp", "rax", 2)])
    assert _stub_slot(loaded, 0x1000) == (0xFE7, "RIP_LOAD_THEN_JUMP_RAX")
    unrelated = _Pe([_Instruction("mov", "rcx, qword ptr [rip + 0x20]", 7),
                     _Instruction("call", "rax", 2)])
    assert _stub_slot(unrelated, 0x1000) is None


def test_non_rip_dispatch_forms_remain_unresolved() -> None:
    assert _classification("qword ptr [rax + 0x118]") == (
        "OBJECT_OR_VTABLE_SLOT", {"base_register": "rax", "byte_offset": 0x118})
    assert _classification("r15") == ("REGISTER_TARGET", {"target_register": "r15"})
    assert _classification("qword ptr [rax]")[0] == "OTHER_INDIRECT_FORM"


def test_nearest_writer_honors_register_aliases() -> None:
    rows = [
        {"rva": 1, "regs_write": ["rax"], "operands": "rax, qword ptr [rcx]"},
        {"rva": 2, "regs_write": ["eax"], "operands": "eax, 1"},
        {"rva": 3, "regs_write": [], "operands": "rcx, rdx"},
    ]
    assert _nearest_linear_writer(rows, 3, "rax")["rva"] == 2


def test_unresolved_slot_account_unions_direct_and_register_loaded_slots() -> None:
    records = [
        {"dispatch_form": "RIP_GLOBAL_SLOT", "slot_rva": 0x1000,
         "resolution_status": "UNRESOLVED_RIP_SLOT_IDENTITY"},
        {"dispatch_form": "RIP_GLOBAL_SLOT", "slot_rva": 0x2000,
         "resolution_status": "UNRESOLVED_RIP_SLOT_IDENTITY"},
        {"dispatch_form": "REGISTER_TARGET", "resolution_status": "STATIC_TARGET_UNRESOLVED",
         "local_dataflow": {"status": "REGISTER_TARGET_LOADED_FROM_RIP_SLOT",
                            "slot_rva": 0x2000}},
        {"dispatch_form": "REGISTER_TARGET", "resolution_status": "STATIC_TARGET_UNRESOLVED",
         "local_dataflow": {"status": "REGISTER_TARGET_LOADED_FROM_RIP_SLOT",
                            "slot_rva": 0x3000}},
        {"dispatch_form": "RIP_GLOBAL_SLOT", "slot_rva": 0x4000,
         "resolution_status": "EXACT_WRAPPER_SLOT_IDENTITY"},
    ]
    assert _unresolved_slot_account(records) == {
        "unresolved_rip_callsite_slots": 2,
        "register_loaded_rip_slots": 2,
        "unique_runtime_slot_candidates_without_exact_identity": 3,
    }
