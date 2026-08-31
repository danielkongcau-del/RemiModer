from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_base_identity_join import _analyze_window, _stable_this_aliases


def _row(rva: int, mnemonic: str, operands: str, writes=(), groups=()):
    return {"rva": rva, "mnemonic": mnemonic, "operands": operands,
            "regs_write": list(writes), "groups": list(groups)}


def test_nonvolatile_prologue_this_alias_survives_call() -> None:
    ins = [_row(1, "mov", "rdi, rcx", ("rdi",)),
           _row(2, "call", "0x20", ("rsp",), ("call",)),
           _row(3, "test", "rax, rax", ("rflags",))]
    assert _stable_this_aliases(ins, 4) == {"rdi": 1}


def test_exact_field_chain_proves_tested_object() -> None:
    window = [_row(10, "mov", "rax, qword ptr [rdi + 0x50]", ("rax",)),
              _row(14, "mov", "rcx, qword ptr [rax + 0x30]", ("rcx",)),
              _row(18, "test", "rcx, rcx", ("rflags",))]
    fields = {
        ("Executor", 0x50): [{"class": "Executor", "field": "config",
                              "materializedClass": "Config", "offset": "0x50", "token": "1"}],
        ("Config", 0x30): [{"class": "Config", "field": "target",
                            "materializedClass": "Target", "offset": "0x30", "token": "2"}],
    }
    result = _analyze_window(window, {"rdi": 1}, "Executor", fields)
    assert result["selected_tested_value_provenance"]["class"] == "Target"
    assert result["accesses"][1]["exact_field"]["field"] == "target"
