from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_unobserved_branch_runtime_plan import (
    _near_relocation_span, _predicate_reads, _rip_target,
)


REFS = ["static"]


def _predicate(shape: str, prior: dict, outcome: str = "FALLTHROUGH") -> dict:
    return {"predicate_machine_shape": shape, "selected_branch": {
        "preceding_instruction_window": [
            {"rva": prior["rva"] - 4, "bytes": "90", "mnemonic": "nop", "operands": ""},
            prior],
        "mnemonic": "je",
        "required_outcome": outcome,
    }}


def test_rip_byte_target_and_read_are_exact_module_relative() -> None:
    ins = {"rva": 0x100, "size": 7, "bytes": "803df9ffffff00",
           "mnemonic": "cmp", "operands": "byte ptr [rip - 0x7], 0"}
    assert _rip_target(ins) == 0x100
    reads, contract = _predicate_reads(
        _predicate("RIP_RELATIVE_MEMORY_COMPARE_ZERO", ins),
        {"stable_nonvolatile_this_aliases": {}}, REFS)
    assert reads[0]["base"] == "module:game"
    assert reads[0]["offset"] == 0x100
    assert contract["semantic_gameplay_predicate_assigned"] is False


def test_rip_target_derives_absent_size_from_authoritative_bytes() -> None:
    ins = {"rva": 0x100, "bytes": "803df9ffffff00", "mnemonic": "cmp",
           "operands": "byte ptr [rip - 0x7], 0"}
    assert _rip_target(ins) == 0x100


def test_exact_field_chain_is_kept_as_control_without_gameplay_semantics() -> None:
    prior = {"rva": 0x20, "bytes": "4885c9", "mnemonic": "test",
             "operands": "rcx, rcx"}
    predicate = _predicate("REGISTER_ZERO_TEST", prior)
    predicate["selected_branch"]["preceding_instruction_window"][0] = {
        "rva": 0x1C, "bytes": "488b08", "mnemonic": "mov",
        "operands": "rcx, qword ptr [rax + 0x30]"}
    base = {
        "stable_nonvolatile_this_aliases": {"rdi": 1},
        "selected_tested_value_provenance": {"kind": "EXACT_FIELD_LOAD", "class": "Target"},
        "accesses": [
            {"rva": 0x10, "base_register": "rdi", "offset": 0x50,
             "base_provenance": {"kind": "THIS_ALIAS"},
             "exact_field": {"class": "Executor", "field": "config"}},
            {"rva": 0x1C, "base_register": "rax", "offset": 0x30,
             "base_provenance": {"kind": "EXACT_FIELD_LOAD", "origin_rva": 0x10},
             "exact_field": {"class": "Config", "field": "target"}},
        ],
    }
    reads, contract = _predicate_reads(predicate, base, REFS)
    by_id = {row["id"]: row for row in reads}
    assert by_id["exact-field-Executor-config"]["base"] == "this-alias-rdi"
    assert by_id["exact-field-Config-target"]["base"] == "exact-field-Executor-config"
    assert contract["exact_tested_object_provenance"]["class"] == "Target"


def test_near_span_uses_whole_instructions_only() -> None:
    assert _near_relocation_span([
        {"size": 3}, {"size": 6}, {"size": 4},
    ]) == 9
