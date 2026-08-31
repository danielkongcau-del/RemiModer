from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_initialized_slot_consumer_join import join


def test_direct_and_register_loaded_consumers_join_by_slot_rva() -> None:
    slots = {"schema": "uc.ability-initialized-slot-import-join.v1",
             "initialized_slots": [
                 {"slot_rva": 0x100, "import": {"name": "Imported"}},
                 {"slot_rva": 0x200, "import": None},
             ]}
    indirect = {"schema": "uc.ability-executor-indirect-call-join.v1",
                "callsites": [
                    {"slot_rva": 0x100, "site_rva": 1, "caller_type": "A",
                     "caller_method": "M", "dispatch_form": "RIP_GLOBAL_SLOT"},
                    {"local_dataflow": {"slot_rva": 0x200}, "site_rva": 2,
                     "caller_type": "B", "caller_method": "N",
                     "dispatch_form": "REGISTER_TARGET"},
                ]}
    result = join(slots, indirect)
    assert result["summary"]["slots_with_static_consumers"] == 2
    assert result["summary"]["non_import_slots_with_static_consumers"] == 1
    assert result["initialized_slots"][1]["static_consumers"][0][
        "access_form"] == "RIP_SLOT_LOADED_TO_REGISTER"
    assert result["initialized_slots"][1]["initialization_owner_status"] == (
        "UNRESOLVED_NON_IMPORT_INITIALIZER")
