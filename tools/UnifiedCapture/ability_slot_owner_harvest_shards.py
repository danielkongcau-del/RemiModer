"""Shard the authoritative harvested type-index set for bounded private-load scans."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_TARGET_INPUT = ROOT / "extracted/analysis/ability-slot-owner-scan-input-20260831-v1.txt"
DEFAULT_TYPE_DUMP = ROOT / "extracted/dump-final.cs"
TYPE = re.compile(r"^// Type\[(\d+)\]$")


def build(target_input: Path, type_dump: Path, shard_size: int, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    if shard_size <= 0:
        raise ValueError("shard size must be positive")
    target_lines = [line for line in target_input.read_text(encoding="utf-8-sig").splitlines()
                    if line.startswith("TARGET|")]
    if not target_lines:
        raise ValueError("target input contains no targets")
    indexes = []
    for line in type_dump.read_text(encoding="utf-8-sig").splitlines():
        match = TYPE.fullmatch(line)
        if match:
            indexes.append(int(match.group(1)))
    indexes = sorted(set(indexes))
    if not indexes:
        raise ValueError("type dump contains no type indexes")
    out.mkdir(parents=True)
    manifest = {
        "schema": "zzz.ability-slot-owner-scan-shards.v1",
        "sources": {
            "target_input": {"path": str(target_input), "sha256": file_hash(target_input)},
            "type_dump": {"path": str(type_dump), "sha256": file_hash(type_dump)},
        },
        "target_pairs": len(target_lines), "type_indexes": len(indexes),
        "shard_size": shard_size, "shards": [],
    }
    header = ["schema=zzz.ability-slot-owner-scan-input.v1|private-load=true", *target_lines]
    for ordinal, begin in enumerate(range(0, len(indexes), shard_size)):
        subset = indexes[begin:begin + shard_size]
        path = out / f"shard-{ordinal:04d}.txt"
        path.write_text("\n".join([*header, *(f"TYPE|index={index}" for index in subset)]) + "\n",
                        encoding="utf-8", newline="\n")
        manifest["shards"].append({
            "ordinal": ordinal, "path": str(path.resolve()), "sha256": file_hash(path),
            "count": len(subset), "first_type": subset[0], "last_type": subset[-1],
        })
    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                             encoding="utf-8", newline="\n")
    report = {"schema": manifest["schema"], "manifest": str(manifest_path),
              "sha256": file_hash(manifest_path), "shards": len(manifest["shards"]),
              "type_indexes": len(indexes)}
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-input", type=Path, default=DEFAULT_TARGET_INPUT)
    parser.add_argument("--type-dump", type=Path, default=DEFAULT_TYPE_DUMP)
    parser.add_argument("--shard-size", type=int, default=2048)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.target_input.resolve(), args.type_dump.resolve(), args.shard_size, args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_slot_owner_harvest_shards", error, {
            "target_input": str(args.target_input), "type_dump": str(args.type_dump),
            "shard_size": args.shard_size,
        })
        raise


if __name__ == "__main__":
    run_main(main)
