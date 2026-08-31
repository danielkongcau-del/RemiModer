"""Join unresolved Ability native slots to preserved IL2CPP arena method objects.

The join is mechanical: exact generated 16-byte wrapper cells in the selected
GameAssembly image are matched to code pointers in preserved arena method
objects, which are then validated through their owning class method array.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ability_executor_indirect_call_join import _stub_slot
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_INDIRECT = ROOT / "extracted/analysis/ability-executor-indirect-call-join-20260831-v5/ability-executor-indirect-call-join.json"
DEFAULT_CLASS_LAYOUT = ROOT / "extracted/analysis/class-layout.md"
DEFAULT_CLASS_LIST = ROOT / "extracted/analysis/class-list-final.json"
DEFAULT_ARENA_INDEX = ROOT / "extracted/arena-dump.index"
DEFAULT_ARENA_DIR = ROOT / "extracted/arena"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size, "sha256": file_hash(path)}


def _preserved_game_base(path: Path) -> int:
    match = re.search(r"GameAssembly 基址 (0x[0-9A-Fa-f]+)", path.read_text(encoding="utf-8-sig"))
    if not match:
        raise ValueError("preserved GameAssembly base is absent from class layout evidence")
    return int(match.group(1), 0)


def _generated_wrapper_cells(pe: NativePE, slots: set[int]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for section in pe.sections:
        if not section["flags"] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        data = pe.data[section["raw_pointer"]:section["raw_pointer"] + section["raw_size"]]
        for pattern in (b"\x48\xff\x25", b"\x48\x8b\x05"):
            cursor = 0
            while True:
                cursor = data.find(pattern, cursor)
                if cursor < 0:
                    break
                rva = section["rva"] + cursor
                cursor += 1
                if rva % 16:
                    continue
                joined = _stub_slot(pe, rva)
                if joined is None or joined[0] not in slots:
                    continue
                instructions = list(pe.cs.disasm(pe.bytes_at(rva, 16), pe.image_base + rva))
                terminal_count = 1 if joined[1] == "RIP_MEMORY_JUMP" else 2
                padding = instructions[terminal_count:]
                if not padding or not all(row.mnemonic.startswith("nop") for row in padding):
                    continue
                if sum(row.size for row in instructions) != 16:
                    continue
                result[joined[0]].append({"wrapper_rva": rva, "stub_form": joined[1]})
    return result


class Arena:
    def __init__(self, index_path: Path, directory: Path):
        self.regions = []
        for line_number, line in enumerate(index_path.read_text(encoding="utf-8-sig").splitlines(), 1):
            fields = line.split()
            if len(fields) != 3:
                raise ValueError(f"invalid arena index line {line_number}")
            name, address, size = fields
            path = directory / f"{name}.bin"
            data = path.read_bytes()
            if len(data) != int(size, 0):
                raise ValueError(f"arena region size mismatch: {path}")
            start = int(address, 16)
            self.regions.append({"start": start, "end": start + len(data), "path": path, "data": data})
        self.regions.sort(key=lambda row: row["start"])
        self.starts = [row["start"] for row in self.regions]

    def read(self, address: int, size: int) -> bytes | None:
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0:
            return None
        row = self.regions[index]
        if address + size > row["end"]:
            return None
        offset = address - row["start"]
        return row["data"][offset:offset + size]

    def qword(self, address: int) -> int | None:
        raw = self.read(address, 8)
        return struct.unpack("<Q", raw)[0] if raw else None

    def string(self, address: int, limit: int = 256) -> str | None:
        raw = self.read(address, limit)
        if raw is None:
            return None
        raw = raw.split(b"\0", 1)[0]
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return value if value and all(char.isprintable() for char in value) else None


def _class_catalog(rows: list[dict[str, Any]]) -> dict[tuple[int, str], list[dict[str, Any]]]:
    result: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        result[(int(row["token"], 0), row["name"])].append({
            key: row.get(key) for key in (
                "name", "ns", "token", "nameIdx", "methods", "vtSlots", "parentName")
        })
    return result


def _validated_method(arena: Arena, pointer_address: int, code_field: int,
                      expected_pointer: int, class_catalog: dict[tuple[int, str], list[dict[str, Any]]]) -> dict[str, Any] | None:
    method = pointer_address - code_field
    if arena.qword(method + code_field) != expected_pointer:
        return None
    klass = arena.qword(method)
    if not klass:
        return None
    name_pointer = arena.qword(klass + 0x50)
    class_name = arena.string(name_pointer) if name_pointer else None
    packed_token = arena.qword(klass + 0xA0)
    method_array = arena.qword(klass + 0x30)
    packed_counts = arena.qword(klass + 0xC0)
    if class_name is None or packed_token is None or method_array is None or packed_counts is None:
        return None
    if packed_token >> 32 != klass & 0xFFFFFFFF:
        return None
    token = packed_token & 0xFFFFFFFF
    method_count = (packed_counts >> 32) & 0xFFFF
    ordinal = None
    for index in range(method_count):
        if arena.qword(method_array + index * 8) == method:
            ordinal = index
            break
    if ordinal is None:
        return None
    class_rows = class_catalog.get((token, class_name), [])
    return {
        "method_object": method, "code_pointer_field": code_field,
        "class_object": klass, "class_name": class_name, "type_token": token,
        "method_ordinal": ordinal, "method_count": method_count,
        "class_list_matches": class_rows,
        "class_identity_status": "EXACT_TOKEN_AND_NAME_CLASS_LIST_MATCH" if len(class_rows) == 1 else (
            "AMBIGUOUS_CLASS_LIST_MATCH" if class_rows else "NO_CLASS_LIST_MATCH"),
        "method_name_status": "NOT_PRESENT_IN_PRESERVED_RAW_METHOD_OBJECT",
    }


def build(indirect_path: Path, class_layout_path: Path, class_list_path: Path,
          arena_index_path: Path, arena_dir: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    indirect = _load(indirect_path)
    if indirect.get("schema") != "uc.ability-executor-indirect-call-join.v1":
        raise ValueError("unsupported indirect call join")
    game_path = Path(indirect["sources"]["game_module"]["path"])
    if file_hash(game_path) != indirect["sources"]["game_module"]["sha256"]:
        raise ValueError("GameAssembly source identity changed")
    pe = NativePE(game_path)
    slots = set()
    for row in indirect["callsites"]:
        if row.get("resolution_status") == "UNRESOLVED_RIP_SLOT_IDENTITY":
            slots.add(int(row["slot_rva"]))
        dataflow = row.get("local_dataflow") or {}
        if dataflow.get("status") == "REGISTER_TARGET_LOADED_FROM_RIP_SLOT":
            slots.add(int(dataflow["slot_rva"]))
    cells = _generated_wrapper_cells(pe, slots)
    arena = Arena(arena_index_path, arena_dir)
    preserved_base = _preserved_game_base(class_layout_path)
    classes = _class_catalog(_load(class_list_path))
    pointer_map = {
        preserved_base + cell["wrapper_rva"]: (slot, cell)
        for slot, values in cells.items() for cell in values
    }
    joined: dict[int, list[dict[str, Any]]] = defaultdict(list)
    hit_regions: set[Path] = set()
    for region in arena.regions:
        data = region["data"]
        aligned = data[:len(data) // 8 * 8]
        for index, unpacked in enumerate(struct.iter_unpack("<Q", aligned)):
            pointer = unpacked[0]
            target = pointer_map.get(pointer)
            if target is None:
                continue
            pointer_address = region["start"] + index * 8
            slot, cell = target
            for code_field in (8, 16):
                method = _validated_method(arena, pointer_address, code_field, pointer, classes)
                if method is None:
                    continue
                record = {**cell, **method, "arena_region": str(region["path"].resolve()),
                          "arena_pointer_offset": index * 8}
                if record not in joined[slot]:
                    joined[slot].append(record)
                    hit_regions.add(region["path"])
    slot_rows = []
    for slot in sorted(slots):
        methods = sorted(joined.get(slot, []), key=lambda row: (
            row["class_name"], row["type_token"], row["method_ordinal"], row["wrapper_rva"]))
        slot_rows.append({
            "slot_rva": slot, "generated_wrapper_cells": cells.get(slot, []),
            "arena_method_candidates": methods,
            "status": "EXACT_CLASS_AND_METHOD_ORDINAL" if methods else (
                "GENERATED_WRAPPER_WITHOUT_ARENA_METHOD_OBJECT" if cells.get(slot) else
                "NO_GENERATED_WRAPPER_CELL"),
        })
    class_counts = Counter(method["class_name"] for methods in joined.values() for method in methods)
    exact_slots = sum(bool(row["arena_method_candidates"]) for row in slot_rows)
    summary = {
        "requested_unresolved_slots": len(slots),
        "slots_with_generated_wrapper_cells": sum(bool(row["generated_wrapper_cells"]) for row in slot_rows),
        "slots_with_exact_arena_class_and_ordinal": exact_slots,
        "slots_without_arena_class_and_ordinal": len(slots) - exact_slots,
        "unique_joined_classes": len(class_counts),
        "joined_class_counts": dict(sorted(class_counts.items())),
    }
    artifact = {
        "schema": "uc.ability-executor-arena-slot-join.v1",
        "sources": {
            "indirect_call_join": _source(indirect_path), "game_module": _source(game_path),
            "class_layout": _source(class_layout_path), "class_list": _source(class_list_path),
            "arena_index": _source(arena_index_path),
            "arena_regions_scanned": [_source(row["path"]) for row in arena.regions],
        },
        "summary": summary,
        "bounded_conclusions": [
            "generated wrapper cells require a 16-byte aligned exact stub form followed only by NOP padding",
            "method objects require exact code pointer, class self-label, and membership in the owning class method array",
            "class identity is joined by exact type token and class name to the independently harvested class list",
            "method ordinal is authoritative but is not promoted to a method name when the raw snapshot contains no name",
            "absence from the preserved arena proves only that this snapshot cannot identify the slot",
        ],
        "runtime_needed_now": False,
        "slots": slot_rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-executor-arena-slot-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-executor-arena-slot-join-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary, "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indirect", type=Path, default=DEFAULT_INDIRECT)
    parser.add_argument("--class-layout", type=Path, default=DEFAULT_CLASS_LAYOUT)
    parser.add_argument("--class-list", type=Path, default=DEFAULT_CLASS_LIST)
    parser.add_argument("--arena-index", type=Path, default=DEFAULT_ARENA_INDEX)
    parser.add_argument("--arena-dir", type=Path, default=DEFAULT_ARENA_DIR)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.indirect.resolve(), args.class_layout.resolve(), args.class_list.resolve(),
                     args.arena_index.resolve(), args.arena_dir.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_executor_arena_slot_join", error, {
            "indirect": str(args.indirect), "class_layout": str(args.class_layout),
            "class_list": str(args.class_list), "arena_index": str(args.arena_index),
            "arena_dir": str(args.arena_dir),
        })
        raise


if __name__ == "__main__":
    run_main(main)
