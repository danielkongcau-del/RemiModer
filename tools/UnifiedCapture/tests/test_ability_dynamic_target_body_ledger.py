from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_dynamic_target_body_ledger import _fast_path_field_load, _immediate_call_pairs


def _ins(rva: int, mnemonic: str, operands: str = "", target: int | None = None) -> dict:
    return {"rva": rva, "mnemonic": mnemonic, "operands": operands,
            "direct_target_rva": target}


def test_exact_field_return_shape_is_mechanical() -> None:
    rows = [_ins(1, "mov", "rax, qword ptr [rsi + 0x28]"),
            _ins(2, "add", "rsp, 0x20"), _ins(3, "pop", "rsi"),
            _ins(4, "ret"), _ins(5, "int3")]
    assert _fast_path_field_load(rows) == {
        "load_rva": 1, "base_register": "rsi", "field_offset": 0x28,
        "return_register": "rax"}
    rows[2] = _ins(3, "pop", "rdi")
    assert _fast_path_field_load(rows) is None


def test_immediate_call_pair_preserves_values_without_semantic_label() -> None:
    rows = [_ins(1, "mov", "ecx, 0x1c0d0"), _ins(6, "call", "0x10", 0x10)]
    assert _immediate_call_pairs(rows) == [{
        "immediate_load_rva": 1, "ecx_immediate": 0x1c0d0,
        "call_rva": 6, "call_target_rva": 0x10}]
