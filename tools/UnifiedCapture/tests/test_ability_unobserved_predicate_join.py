from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_predicate_join import _memory_accesses, _predicate_shape


def test_numeric_field_join_does_not_prove_base_identity() -> None:
    window = [{"rva": 1, "mnemonic": "mov",
               "operands": "rax, qword ptr [rdi + 0x28]"}]
    fields = [{"offset": "0x00000028", "class": "C", "field": "F",
               "materializedClass": "X", "token": "0x1"}]
    row = _memory_accesses(window, fields)[0]
    assert row["field_candidates"][0]["field"] == "F"
    assert row["base_object_identity_proven"] is False


def test_machine_predicate_shape_is_not_semantic() -> None:
    branch = {"preceding_instruction_window": [
        {"mnemonic": "test", "operands": "rcx, rcx"}]}
    assert _predicate_shape(branch) == "REGISTER_ZERO_TEST"
