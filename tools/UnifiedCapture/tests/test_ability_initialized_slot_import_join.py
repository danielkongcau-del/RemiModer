from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_initialized_slot_import_join import join


def test_import_join_uses_slot_rva_not_captured_pointer_guess() -> None:
    runtime = {"schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
               "initialized_slots": [
                   {"slot_rva": 0x100, "values": [{"address": 0xDEADBEEF}]},
                   {"slot_rva": 0x200, "values": [{"address": 0x12345678}]},
               ]}
    result = join(runtime, {0x100: {"module": "KERNEL32.dll", "name": "GetLastError"}})
    assert result["initialized_slots"][0]["slot_identity"] == "PE_IMPORT_ADDRESS_TABLE"
    assert result["initialized_slots"][0]["import"]["name"] == "GetLastError"
    assert result["initialized_slots"][1]["slot_identity"] == "NON_IMPORT_INITIALIZED_SLOT"
    assert result["summary"] == {"initialized_slots": 2, "pe_import_slots": 1,
                                  "non_import_initialized_slots": 1}
