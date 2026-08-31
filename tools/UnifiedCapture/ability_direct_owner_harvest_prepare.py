"""Prepare a bounded private-load owner scan for unidentified direct targets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_FRONTIER = ROOT / "extracted/analysis/ability-executor-dependency-frontier-20260831-v4/ability-executor-dependency-frontier.json"
DEFAULT_CLASS_LIST = ROOT / "extracted/analysis/class-list-final.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(frontier_path: Path, class_list_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    frontier = _load(frontier_path)
    if frontier.get("schema") != "uc.ability-executor-dependency-frontier.v1":
        raise ValueError("unsupported dependency frontier")
    targets = sorted(int(row["target_rva"]) for row in frontier["direct_targets"]
                     if not row["source_identities"] and not row["source_annotations"])
    indexes = sorted(set(int(row["nameIdx"]) for row in _load(class_list_path)))
    lines = [
        "schema=zzz.ability-direct-owner-scan-input.v1|private-load=true",
        f"SOURCE|frontier={frontier_path.resolve()}|sha256={file_hash(frontier_path)}",
        f"SOURCE|class-list={class_list_path.resolve()}|sha256={file_hash(class_list_path)}",
    ]
    lines.extend(f"TARGET|slot=0x{rva:x}|wrapper-rva=0x{rva:x}" for rva in targets)
    lines.extend(f"TYPE|index={index}" for index in indexes)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = {"schema": "zzz.ability-direct-owner-scan-input-report.v1",
              "output": str(out), "sha256": file_hash(out),
              "target_rvas": len(targets), "type_indexes": len(indexes)}
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--class-list", type=Path, default=DEFAULT_CLASS_LIST)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.frontier.resolve(), args.class_list.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_direct_owner_harvest_prepare", error, {
            "frontier": str(args.frontier), "class_list": str(args.class_list),
        })
        raise


if __name__ == "__main__":
    run_main(main)
