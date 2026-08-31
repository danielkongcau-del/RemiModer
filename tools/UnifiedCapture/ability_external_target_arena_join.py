"""Join unidentified Ability direct targets to preserved IL2CPP method objects.

The arena snapshot supplies class ownership and method-array ordinal.  It does
not by itself contain a method-name string, so no name is synthesized here.
"""
from __future__ import annotations

import argparse
import json
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ability_executor_arena_slot_join import (
    Arena, _class_catalog, _preserved_game_base, _source, _validated_method,
)
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_BODY_LEDGER = (
    ROOT / "extracted/analysis/ability-external-target-body-ledger-20260831-v1/"
    "ability-external-target-body-ledger.json"
)
DEFAULT_CLASS_LAYOUT = ROOT / "extracted/analysis/class-layout.md"
DEFAULT_CLASS_LIST = ROOT / "extracted/analysis/class-list-final.json"
DEFAULT_ARENA_INDEX = ROOT / "extracted/arena-dump.index"
DEFAULT_ARENA_DIR = ROOT / "extracted/arena"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def build(body_ledger_path: Path, class_layout_path: Path, class_list_path: Path,
          arena_index_path: Path, arena_dir: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    ledger = _load(body_ledger_path)
    if ledger.get("schema") != "uc.ability-external-target-body-ledger.v1":
        raise ValueError("unsupported external target body ledger")
    game_source = ledger["sources"]["game_module"]
    game_path = Path(game_source["path"])
    if file_hash(game_path) != game_source["sha256"]:
        raise ValueError("GameAssembly source identity changed")
    target_rows = {
        int(row["target_rva"]): row for row in ledger["targets"]
        if not row["source_identified_or_annotated"]
        and row["mechanical_body_class"] != "NO_EXACT_PDATA_ENTRY"
    }
    arena = Arena(arena_index_path, arena_dir)
    preserved_base = _preserved_game_base(class_layout_path)
    classes = _class_catalog(_load(class_list_path))
    pointer_map = {preserved_base + rva: rva for rva in target_rows}
    joined: dict[int, list[dict[str, Any]]] = defaultdict(list)

    for region in arena.regions:
        aligned = region["data"][:len(region["data"]) // 8 * 8]
        for index, unpacked in enumerate(struct.iter_unpack("<Q", aligned)):
            pointer = unpacked[0]
            target_rva = pointer_map.get(pointer)
            if target_rva is None:
                continue
            pointer_address = region["start"] + index * 8
            for code_field in (8, 16):
                method = _validated_method(
                    arena, pointer_address, code_field, pointer, classes)
                if method is None:
                    continue
                record = {
                    **method,
                    "arena_region": str(region["path"].resolve()),
                    "arena_pointer_offset": index * 8,
                }
                key = (record["method_object"], record["code_pointer_field"])
                if not any((old["method_object"], old["code_pointer_field"]) == key
                           for old in joined[target_rva]):
                    joined[target_rva].append(record)

    rows = []
    class_counts: Counter[str] = Counter()
    exact_class_list_targets = 0
    for target_rva, source_row in target_rows.items():
        matches = sorted(joined.get(target_rva, []), key=lambda row: (
            row["class_name"], row["type_token"], row["method_ordinal"],
            row["method_object"]))
        if any(row["class_identity_status"] == "EXACT_TOKEN_AND_NAME_CLASS_LIST_MATCH"
               for row in matches):
            exact_class_list_targets += 1
        for match in matches:
            class_counts[match["class_name"]] += 1
        rows.append({
            "target_rva": target_rva,
            "callsite_count": source_row["callsite_count"],
            "mechanical_body_class": source_row["mechanical_body_class"],
            "arena_method_candidates": matches,
            "status": ("EXACT_CLASS_AND_METHOD_ORDINAL" if matches else
                       "NOT_PRESENT_IN_PRESERVED_ARENA"),
        })
    rows.sort(key=lambda row: (-row["callsite_count"], row["target_rva"]))
    matched_targets = sum(bool(row["arena_method_candidates"]) for row in rows)
    summary = {
        "requested_unidentified_exact_pdata_targets": len(rows),
        "targets_with_arena_method_candidate": matched_targets,
        "targets_with_exact_class_list_identity": exact_class_list_targets,
        "targets_not_present_in_preserved_arena": len(rows) - matched_targets,
        "unique_joined_classes": len(class_counts),
        "joined_class_counts": dict(sorted(class_counts.items())),
    }
    artifact = {
        "schema": "uc.ability-external-target-arena-join.v1",
        "sources": {
            "external_target_body_ledger": _source(body_ledger_path),
            "game_module": _source(game_path),
            "class_layout": _source(class_layout_path),
            "class_list": _source(class_list_path),
            "arena_index": _source(arena_index_path),
            "arena_regions_scanned": [_source(row["path"]) for row in arena.regions],
        },
        "summary": summary,
        "bounded_conclusions": [
            "each positive join requires the exact preserved code pointer, class self-label, and owning method-array membership",
            "class identity is exact only when token and name uniquely match the independent class list",
            "method ordinal is not promoted to a method name without a separate authoritative ordinal-to-name source",
            "absence proves only that the preserved loading-phase arena snapshot cannot identify the target",
        ],
        "runtime_needed_now": False,
        "targets": rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-external-target-arena-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-external-target-arena-join-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body-ledger", type=Path, default=DEFAULT_BODY_LEDGER)
    parser.add_argument("--class-layout", type=Path, default=DEFAULT_CLASS_LAYOUT)
    parser.add_argument("--class-list", type=Path, default=DEFAULT_CLASS_LIST)
    parser.add_argument("--arena-index", type=Path, default=DEFAULT_ARENA_INDEX)
    parser.add_argument("--arena-dir", type=Path, default=DEFAULT_ARENA_DIR)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.body_ledger.resolve(), args.class_layout.resolve(),
                     args.class_list.resolve(), args.arena_index.resolve(),
                     args.arena_dir.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_external_target_arena_join", error, {
            "body_ledger": str(args.body_ledger), "class_layout": str(args.class_layout),
            "class_list": str(args.class_list), "arena_index": str(args.arena_index),
            "arena_dir": str(args.arena_dir),
        })
        raise


if __name__ == "__main__":
    run_main(main)
