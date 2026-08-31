"""Split an existing bounded private-load scan input into smaller shards."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def build(scan_input: Path, shard_size: int, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    if shard_size <= 0:
        raise ValueError("shard size must be positive")
    lines = scan_input.read_text(encoding="utf-8-sig").splitlines()
    targets = [line for line in lines if line.startswith("TARGET|")]
    types = sorted({int(line.split("=", 1)[1]) for line in lines
                    if line.startswith("TYPE|index=")})
    if not targets or not types:
        raise ValueError("scan input requires TARGET and TYPE rows")
    out.mkdir(parents=True)
    shards = []
    header = [
        "schema=zzz.ability-scan-input-reshard.v1|private-load=true",
        f"SOURCE|input={scan_input.resolve()}|sha256={file_hash(scan_input)}",
        *targets,
    ]
    for ordinal, begin in enumerate(range(0, len(types), shard_size)):
        subset = types[begin:begin + shard_size]
        path = out / f"shard-{ordinal:04d}.txt"
        path.write_text("\n".join([
            *header, *(f"TYPE|index={index}" for index in subset)
        ]) + "\n", encoding="utf-8", newline="\n")
        shards.append({
            "ordinal": ordinal,
            "path": str(path.resolve()),
            "sha256": file_hash(path),
            "count": len(subset),
            "first_type": subset[0],
            "last_type": subset[-1],
        })
    manifest = {
        "schema": "zzz.ability-scan-input-shards.v1",
        "sources": {"scan_input": {
            "path": str(scan_input.resolve()), "sha256": file_hash(scan_input)}},
        "target_pairs": len(targets),
        "type_indexes": len(types),
        "shard_size": shard_size,
        "shards": shards,
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_bytes(canonical(manifest))
    report = {
        "schema": "zzz.ability-scan-input-shards-report.v1",
        "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "target_pairs": len(targets), "type_indexes": len(types),
        "shard_size": shard_size, "shards": len(shards),
    }
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--shard-size", type=int, default=128)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.input.resolve(), args.shard_size, args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_scan_input_reshard", error, {
            "input": str(args.input), "shard_size": args.shard_size,
        })
        raise


if __name__ == "__main__":
    run_main(main)
