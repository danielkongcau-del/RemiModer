from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from int_comparison_enum_decode import _case_predicates, _enum_layout


def test_layout_and_native_case_binding() -> None:
    text = """
IntComparison : Conditional {
 public Operation operation; // 0x60
}
Operation : Enum {
 public const Operation LessThan;
 public const Operation EqualTo;
 public const Operation GreaterThan;
 public int value__; // 0x10
}
"""
    # The production enum has six values; retain that invariant in the fixture.
    text = text.replace(" public const Operation EqualTo;", """ public const Operation LessThanOrEqualTo;
 public const Operation EqualTo;
 public const Operation NotEqualTo;
 public const Operation GreaterThanOrEqualTo;""")
    members, offset = _enum_layout(text)
    assert members[2] == "EqualTo"
    assert offset == 0x60
    instructions = [
        {"rva": 0x10, "mnemonic": "jmp", "direct_target_rva": 0x30},
        {"rva": 0x20, "mnemonic": "jmp", "direct_target_rva": 0x40},
        {"rva": 0x30, "mnemonic": "cmp", "direct_target_rva": None},
        {"rva": 0x31, "mnemonic": "sete", "direct_target_rva": None},
        {"rva": 0x40, "mnemonic": "cmp", "direct_target_rva": None},
        {"rva": 0x41, "mnemonic": "setne", "direct_target_rva": None},
    ]
    rows = _case_predicates(instructions, [0x10, 0x20])
    assert [row["native_predicate"] for row in rows] == ["equal", "not_equal"]
