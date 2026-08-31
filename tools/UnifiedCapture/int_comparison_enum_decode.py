"""Mechanically bind IntComparison serialized enum values to native predicates."""
from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


TYPE_AND_ENUM = re.compile(
    r"IntComparison\s*:\s*Conditional\s*\{(?P<type_body>.*?)\}"
    r".*?Operation\s*:\s*Enum\s*\{(?P<enum_body>.*?)\}", re.DOTALL)
ENUM_MEMBER = re.compile(r"public const Operation\s+(?P<name>[A-Za-z0-9_]+)\s*;")
OPERATION_FIELD = re.compile(r"public Operation operation;\s*//\s*(?P<offset>0x[0-9a-fA-F]+)")
SETCC = {
    "setl": "signed_less_than", "setle": "signed_less_than_or_equal",
    "sete": "equal", "setne": "not_equal",
    "setge": "signed_greater_than_or_equal", "setg": "signed_greater_than",
}


def _enum_layout(text: str) -> tuple[list[str], int]:
    matched = TYPE_AND_ENUM.search(text)
    if not matched:
        raise ValueError("IntComparison Operation enum or field offset not found")
    field = OPERATION_FIELD.search(matched.group("type_body"))
    if not field:
        raise ValueError("IntComparison operation field offset not found")
    members = ENUM_MEMBER.findall(matched.group("enum_body"))
    if len(members) != 6:
        raise ValueError(f"expected six Operation members, found {len(members)}")
    return members, int(field.group("offset"), 16)


def _case_predicates(instructions: list[dict[str, Any]], targets: list[int]) -> list[dict[str, Any]]:
    by_rva = {row["rva"]: row for row in instructions}
    positions = {row["rva"]: index for index, row in enumerate(instructions)}
    result = []
    for target in targets:
        if target not in positions:
            raise ValueError(f"case target is not decoded: {target:#x}")
        transfer = None
        for row in instructions[positions[target]:]:
            if row["mnemonic"] == "jmp" and row.get("direct_target_rva") is not None:
                transfer = row
                break
        if transfer is None:
            raise ValueError(f"case has no direct comparison transfer: {target:#x}")
        compare_rva = transfer["direct_target_rva"]
        compare_index = positions.get(compare_rva)
        if compare_index is None:
            raise ValueError(f"comparison target is not decoded: {compare_rva:#x}")
        predicate = None
        predicate_row = None
        for row in instructions[compare_index:compare_index + 8]:
            if row["mnemonic"] in SETCC:
                predicate = SETCC[row["mnemonic"]]
                predicate_row = row
                break
        if predicate is None:
            raise ValueError(f"comparison target has no supported setcc: {compare_rva:#x}")
        result.append({
            "case_target_rva": target,
            "comparison_rva": compare_rva,
            "predicate_instruction_rva": predicate_row["rva"],
            "predicate_instruction": predicate_row["mnemonic"],
            "native_predicate": predicate,
        })
    return result


def run(type_layout: Path, module: Path, output: Path,
        function_rva: int = 0x1E471EB0, jump_table_rva: int = 0x2902408) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    members, operation_offset = _enum_layout(type_layout.read_text(encoding="utf-8-sig"))
    image = NativePE(module)
    owner = image.containing(function_rva)
    if owner is None or owner.begin != function_rva:
        raise ValueError("IntComparison.OnUpdate runtime function boundary not found")
    decoded = image.decode(owner)
    if not decoded["all_declared_bytes_decoded"]:
        raise ValueError("IntComparison.OnUpdate is not completely decoded")
    table_bytes = image.bytes_at(jump_table_rva, 4 * len(members))
    relative_targets = struct.unpack(f"<{len(members)}i", table_bytes)
    targets = [jump_table_rva + value for value in relative_targets]
    cases = _case_predicates(decoded["instructions"], targets)
    mappings = [{"raw_value": index, "enum_member": members[index], **case}
                for index, case in enumerate(cases)]
    artifact = {
        "schema": "uc.int-comparison-enum-decode.v1",
        "sources": {
            "runtime_type_layout": {"path": str(type_layout), "sha256": file_hash(type_layout)},
            "game_module": {"path": str(module), "sha256": file_hash(module)},
        },
        "type": "BehaviorDesigner.Runtime.Tasks.Unity.Math.IntComparison",
        "operation_field_offset": operation_offset,
        "on_update": {
            "function_rva": function_rva,
            "function_end_rva": owner.end,
            "jump_table_rva": jump_table_rva,
            "jump_table_bytes": table_bytes.hex(),
            "complete_native_decode": True,
        },
        "mappings": mappings,
        "selected_runtime_value": next(row for row in mappings if row["raw_value"] == 2),
        "semantic_limit": "numeric values are bound by the native jump table; predicates are the executed x64 setcc operations",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(artifact))
    print(json.dumps({"ok": True, "output": str(output),
                      "selected_runtime_value": artifact["selected_runtime_value"]}, ensure_ascii=False))
    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--function-rva", type=lambda value: int(value, 0), default=0x1E471EB0)
    parser.add_argument("--jump-table-rva", type=lambda value: int(value, 0), default=0x2902408)
    args = parser.parse_args()
    run(args.type_layout.resolve(), args.module.resolve(), args.out.resolve(),
        args.function_rva, args.jump_table_rva)
