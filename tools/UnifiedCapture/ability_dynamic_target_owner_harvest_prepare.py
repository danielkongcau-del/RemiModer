"""Prepare a private-load owner scan for unresolved observed dynamic targets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(method_join_path: Path, class_list_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    method_join = _load(method_join_path)
    if method_join.get("schema") != (
            "uc.ability-dynamic-dispatch-authoritative-method-join.v1"):
        raise ValueError("unsupported authoritative dynamic method join")
    targets = sorted(int(row["target_rva"]) for row in method_join["targets"]
                     if not row.get("method_candidates"))
    indexes = sorted(set(int(row["nameIdx"]) for row in _load(class_list_path)))
    lines = [
        "schema=zzz.ability-dynamic-target-owner-scan-input.v1|private-load=true",
        f"SOURCE|method-join={method_join_path.resolve()}|sha256={file_hash(method_join_path)}",
        f"SOURCE|class-list={class_list_path.resolve()}|sha256={file_hash(class_list_path)}",
        *(f"TARGET|slot=0x{rva:x}|wrapper-rva=0x{rva:x}" for rva in targets),
        *(f"TYPE|index={index}" for index in indexes),
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    result = {"schema": "zzz.ability-dynamic-target-owner-scan-input-report.v1",
              "output": str(out.resolve()), "sha256": file_hash(out),
              "target_rvas": len(targets), "type_indexes": len(indexes)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("method_join", type=Path)
    parser.add_argument("class_list", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        return build(args.method_join, args.class_list, args.output)
    except Exception as error:
        write_failure(args.output, "ability_dynamic_target_owner_harvest_prepare", error, {
            "method_join": str(args.method_join), "class_list": str(args.class_list)})
        raise


if __name__ == "__main__":
    run_main(main)
