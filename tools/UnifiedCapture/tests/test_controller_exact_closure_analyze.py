from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_exact_closure_analyze import (
    _condition_signature,
    _decode_system_string,
    _join_lifecycle,
)


def test_source_layout_string_decoder_uses_length_and_first_char_offsets() -> None:
    text = "ActionMode"
    block = bytearray(96)
    block[16:20] = len(text).to_bytes(4, "little", signed=True)
    block[20:20 + len(text) * 2] = text.encode("utf-16-le")
    assert _decode_system_string(bytes(block), {"status": 1, "offset": 0, "length": 96}) == text
    assert _decode_system_string(bytes(block), {"status": 3, "offset": 0, "length": 96}) is None


def test_condition_signature_never_uses_runtime_index_as_serialized_identity() -> None:
    row = {"integer1_shared_name": "Int_ActiveSkill", "integer2_constant_raw": 2,
           "operation_raw": 2, "runtime_task_index": 999}
    assert _condition_signature(row) == ("Int_ActiveSkill", 2, 2)


def test_lifecycle_join_requires_same_address_and_later_destroy_boundary() -> None:
    loads = [{"behavior": 10, "qpc": 100}, {"behavior": 20, "qpc": 100}]
    destroys = [{"behavior": 10, "qpc": 90, "execution_status": 1},
                {"behavior": 10, "qpc": 120, "execution_status": 2}]
    rows = _join_lifecycle(loads, destroys)
    assert rows[0]["destroy_observed"] is True
    assert rows[0]["destroy_qpc"] == 120
    assert rows[1]["destroy_observed"] is False
