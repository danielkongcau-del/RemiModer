"""Prepare a bounded private-load slot-owner scan input from authoritative artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_ARENA_JOIN = ROOT / "extracted/analysis/ability-executor-arena-slot-join-20260831-v2/ability-executor-arena-slot-join.json"
DEFAULT_CLASS_LIST = ROOT / "extracted/analysis/class-list-final.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(arena_join_path: Path, class_list_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    arena_join = _load(arena_join_path)
    if arena_join.get("schema") != "uc.ability-executor-arena-slot-join.v1":
        raise ValueError("unsupported arena slot join")
    targets = []
    for row in arena_join["slots"]:
        if row["status"] != "GENERATED_WRAPPER_WITHOUT_ARENA_METHOD_OBJECT":
            continue
        for cell in row["generated_wrapper_cells"]:
            targets.append((int(row["slot_rva"]), int(cell["wrapper_rva"])))
    targets = sorted(set(targets))
    type_indexes = sorted(set(int(row["nameIdx"]) for row in _load(class_list_path)))
    lines = [
        "schema=zzz.ability-slot-owner-scan-input.v1|private-load=true",
        f"SOURCE|arena-join={arena_join_path.resolve()}|sha256={file_hash(arena_join_path)}",
        f"SOURCE|class-list={class_list_path.resolve()}|sha256={file_hash(class_list_path)}",
    ]
    lines.extend(f"TARGET|slot=0x{slot:x}|wrapper-rva=0x{wrapper:x}" for slot, wrapper in targets)
    lines.extend(f"TYPE|index={index}" for index in type_indexes)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = {
        "schema": "zzz.ability-slot-owner-scan-input-report.v1",
        "output": str(out), "sha256": file_hash(out),
        "target_wrapper_pairs": len(targets), "type_indexes": len(type_indexes),
    }
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arena-join", type=Path, default=DEFAULT_ARENA_JOIN)
    parser.add_argument("--class-list", type=Path, default=DEFAULT_CLASS_LIST)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.arena_join.resolve(), args.class_list.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_slot_owner_harvest_prepare", error, {
            "arena_join": str(args.arena_join), "class_list": str(args.class_list),
        })
        raise


if __name__ == "__main__":
    run_main(main)
