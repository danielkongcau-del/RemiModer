"""Prepare retry input containing only incomplete private-load scan shards."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ability_slot_owner_scan_analyze import SUMMARY
from uc.cli import run_main, write_failure
from uc.model import file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(manifest_path: Path, results_dir: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    manifest = _load(manifest_path)
    retry_types: set[int] = set()
    targets: set[str] = set()
    incomplete = []
    for shard in manifest["shards"]:
        shard_path = Path(shard["path"])
        lines = shard_path.read_text(encoding="utf-8-sig").splitlines()
        targets.update(line for line in lines if line.startswith("TARGET|"))
        output = results_dir / (shard_path.stem + ".out.txt")
        complete = False
        if output.is_file():
            summaries = [SUMMARY.fullmatch(line) for line in output.read_text(
                encoding="utf-8-sig", errors="replace").splitlines()
                         if line.startswith("SUMMARY|")]
            summaries = [row for row in summaries if row]
            complete = (len(summaries) == 1
                        and int(summaries[0].group(1)) == int(shard["count"]))
        if complete:
            continue
        incomplete.append(int(shard["ordinal"]))
        retry_types.update(int(line.split("=", 1)[1]) for line in lines
                           if line.startswith("TYPE|index="))
    if not retry_types:
        raise ValueError("no incomplete types to retry")
    lines = [
        "schema=zzz.ability-private-load-retry-input.v1|private-load=true",
        f"SOURCE|manifest={manifest_path.resolve()}|sha256={file_hash(manifest_path)}",
        *sorted(targets),
        *(f"TYPE|index={index}" for index in sorted(retry_types)),
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = {"schema": "zzz.ability-private-load-retry-input-report.v1",
              "output": str(out.resolve()), "sha256": file_hash(out),
              "incomplete_shards": len(incomplete),
              "incomplete_shard_ordinals": incomplete,
              "target_pairs": len(targets), "type_indexes": len(retry_types)}
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("results_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        return build(args.manifest, args.results_dir, args.output)
    except Exception as error:
        write_failure(args.output, "ability_scan_retry_prepare", error, {
            "manifest": str(args.manifest), "results_dir": str(args.results_dir)})
        raise


if __name__ == "__main__":
    run_main(main)
