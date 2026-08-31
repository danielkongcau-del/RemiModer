from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_initialized_slot_module_join import _candidate_bases


def test_aslr_translation_uses_whole_exact_entry_set() -> None:
    base = 0x7FFB00000000
    targets = {base + 0x1100, base + 0x2200, base + 0x3300}
    rows = _candidate_bases(targets, {0x1100, 0x2200, 0x3300}, 0x10000)
    assert rows[0] == {"runtime_base": base, "exact_pdata_starts": 3,
                       "inside_pdata_ranges": 3}


def test_partial_translation_is_not_full_match() -> None:
    base = 0x7FFB00000000
    rows = _candidate_bases({base + 0x1100, base + 0x2200}, {0x1100}, 0x10000)
    assert rows[0]["exact_pdata_starts"] == 1
