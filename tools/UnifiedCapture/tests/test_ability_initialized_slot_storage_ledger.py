from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_initialized_slot_storage_ledger import _classify_rva


class _Image:
    sections = [{
        "name": ".data", "rva": 0x1000, "virtual_size": 0x300,
        "raw_size": 0x100, "raw_pointer": 0x400, "flags": 0,
    }]


def test_file_backed_section_prefix() -> None:
    row = _classify_rva(_Image(), 0x1080)
    assert row["storage_class"] == "FILE_BACKED"
    assert row["file_offset"] == 0x480


def test_virtual_zero_fill_tail() -> None:
    row = _classify_rva(_Image(), 0x1180)
    assert row["storage_class"] == "VIRTUAL_ZERO_FILL_TAIL"
    assert row["file_offset"] is None
