from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caller_candidate_ghidra_join import build


def test_instruction_agreement_and_external_references_are_separate():
    static = {"functions": [{"module": "unity", "begin_rva": 0x100,
        "end_rva": 0x110, "instructions": [{"rva": 0x100, "bytes": "90",
                                              "mnemonic": "nop"}]}]}
    exported = [{"runtime_begin_rva": str(0x100), "instruction_rva": str(0x100),
        "bytes": "90", "mnemonic": "NOP", "incoming_reference_rvas": "257,512"}]
    result = build(static, {"schema": "fixture"}, exported)
    row = result["functions"][0]
    assert row["instruction_agreement"] is True
    assert row["incoming_reference_rvas"] == [0x101, 0x200]
    assert row["external_incoming_reference_rvas"] == [0x200]

    static["functions"][0]["instructions"][0].update(bytes="7401", mnemonic="je")
    exported[0].update(bytes="7401", mnemonic="JZ")
    assert build(static, {}, exported)["functions"][0]["instruction_agreement"] is True
