from __future__ import annotations

from pathlib import Path
import sys

from capstone import CS_AC_READ, CS_AC_WRITE

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_initialized_slot_pdata_xrefs import _access_kind


def test_decoder_access_flags_remain_explicit() -> None:
    assert _access_kind(CS_AC_READ) == "READ"
    assert _access_kind(CS_AC_WRITE) == "WRITE"
    assert _access_kind(CS_AC_READ | CS_AC_WRITE) == "READ_WRITE"
    assert _access_kind(0) == "ACCESS_UNSPECIFIED_BY_DECODER"
