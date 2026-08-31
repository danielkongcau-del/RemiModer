from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from task_reset_dispatch_audit import _offset_operand


def test_virtual_slot_operand_is_exact() -> None:
    assert _offset_operand(0x158) == "+ 0x158]"
    assert _offset_operand(0x58) != "+ 0x158]"
