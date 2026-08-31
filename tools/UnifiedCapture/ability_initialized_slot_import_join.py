"""Resolve captured initialized-slot RVAs against the source PE import table."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated PE import string")
    return data[offset:end].decode("ascii", errors="strict")


def import_slots(path: Path) -> dict[int, dict[str, Any]]:
    image = NativePE(path)
    data = image.data
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    import_rva, import_size = struct.unpack_from("<II", data, optional + 112 + 8)
    if not import_rva or not import_size:
        return {}
    cursor = image.offset(import_rva)
    result: dict[int, dict[str, Any]] = {}
    for _ in range(import_size // 20 + 1):
        original, stamp, forward, name_rva, first = struct.unpack_from("<IIIII", data, cursor)
        cursor += 20
        if not any((original, stamp, forward, name_rva, first)):
            break
        module = _cstring(data, image.offset(name_rva))
        lookup = original or first
        index = 0
        while True:
            thunk, = struct.unpack_from("<Q", data, image.offset(lookup + index * 8))
            if not thunk:
                break
            slot_rva = first + index * 8
            if thunk & (1 << 63):
                row = {"module": module, "ordinal": thunk & 0xFFFF, "name": None}
            else:
                hint_offset = image.offset(int(thunk))
                hint, = struct.unpack_from("<H", data, hint_offset)
                row = {"module": module, "ordinal": None,
                       "hint": hint, "name": _cstring(data, hint_offset + 2)}
            if slot_rva in result:
                raise ValueError(f"duplicate PE import slot RVA: {slot_rva:#x}")
            result[slot_rva] = row
            index += 1
    return result


def join(runtime: dict[str, Any], imports: dict[int, dict[str, Any]]) -> dict[str, Any]:
    if runtime.get("schema") != "uc.ability-dynamic-dispatch-runtime-analysis.v1":
        raise ValueError("unsupported dynamic-dispatch runtime analysis")
    rows = []
    for slot in runtime["initialized_slots"]:
        rva = int(slot["slot_rva"])
        match = imports.get(rva)
        rows.append({**slot,
                     "slot_identity": "PE_IMPORT_ADDRESS_TABLE" if match else "NON_IMPORT_INITIALIZED_SLOT",
                     "import": match})
    return {"initialized_slots": rows,
            "summary": {"initialized_slots": len(rows),
                        "pe_import_slots": sum(row["import"] is not None for row in rows),
                        "non_import_initialized_slots": sum(row["import"] is None for row in rows)}}


def analyze(runtime_path: Path, game_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    runtime = _load(runtime_path)
    if runtime.get("module", {}).get("sha256") != file_hash(game_path):
        raise ValueError("runtime GameAssembly identity differs from import source")
    result = {
        "schema": "uc.ability-initialized-slot-import-join.v1",
        "sources": {"runtime_analysis": _source(runtime_path),
                    "game_module": _source(game_path)},
        "bounded_conclusions": [
            "an exact slot-RVA match identifies a PE import-address-table entry",
            "captured target addresses are retained separately and are not used to guess module identity",
            "non-import initialized slots remain unresolved by this join",
        ],
        **join(runtime, import_slots(game_path)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(result))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_analysis", type=Path)
    parser.add_argument("game_module", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.runtime_analysis, args.game_module, args.output)
    except Exception as error:
        write_failure(args.output, "ability_initialized_slot_import_join", error, {
            "runtime_analysis": str(args.runtime_analysis), "game_module": str(args.game_module)})
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
