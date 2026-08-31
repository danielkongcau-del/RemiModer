from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_nested_condition_analyze import _decode_string, _verify_layout


ROOT = Path(__file__).resolve().parents[3]


def test_source_verified_system_string_decode() -> None:
    value = "Int_ActiveSkill"
    encoded = value.encode("utf-16-le")
    block = bytearray(96)
    block[16:20] = len(value).to_bytes(4, "little", signed=True)
    block[20:20 + len(encoded)] = encoded
    assert _decode_string(bytes(block), {"status": 1, "offset": 0, "length": 96}) == value


def test_runtime_layout_source_contains_nested_condition_contract() -> None:
    source = ROOT / "extracted/dump-x-xa.cs"
    if source.is_file():
        _verify_layout(source)
