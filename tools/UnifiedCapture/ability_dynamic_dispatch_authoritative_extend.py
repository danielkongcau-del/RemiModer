"""Extend dynamic target identities from preserved runtime method harvests.

Only exact target-RVA matches are accepted.  The runtime receiver class remains
separate from the declaring class recorded by a method harvest.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any, Iterable

from ability_executor_dependency_frontier import _merge_catalogs
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _attributes(parts: Iterable[str]) -> dict[str, str]:
    result = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            result[key] = value
    return result


def labeled_runtime_catalog(path: Path) -> dict[int, list[dict[str, Any]]]:
    """Parse the label-based runtime field/method harvest format."""
    classes: dict[str, dict[str, Any]] = {}
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for line_number, raw in enumerate(path.read_text(
            encoding="utf-8-sig", errors="strict").splitlines(), 1):
        parts = raw.split("|")
        if not parts:
            continue
        attributes = _attributes(parts[1:])
        label = attributes.get("label")
        if parts[0] == "CLASS" and label:
            classes[label] = {
                "declaring_class": attributes.get("name"),
                "declaring_token": attributes.get("token"),
                "generic_arguments": [],
            }
        elif parts[0] == "ARG" and label and label in classes:
            classes[label]["generic_arguments"].append({
                "index": int(attributes["index"]),
                "name": attributes.get("name"),
                "token": attributes.get("token"),
            })
        elif parts[0] == "METHOD" and label and attributes.get("rva"):
            owner = classes.get(label)
            if owner is None:
                continue
            result[int(attributes["rva"], 0)].append({
                "source": str(path.resolve()),
                "source_line": line_number,
                **owner,
                "method_index": int(attributes["index"]),
                "method_name": attributes.get("name"),
                "harvest_format": "LABELLED_RUNTIME_METHOD",
            })
    return dict(result)


_EFFECT = re.compile(
    r"^hit=(?P<hit>\d+)\s+type=(?P<type>\d+)\s+ordinal=(?P<ordinal>\d+)\s+"
    r"token=(?P<token>0x[0-9a-fA-F]+)\s+namespace=(?P<namespace>\S+)\s+"
    r"class=(?P<class>\S+)\s+method-index=(?P<method_index>\d+)\s+"
    r"method=(?P<method>\S+)\s+method-info=(?P<method_info>[0-9a-fA-F]+)\s+"
    r"code-rva=(?P<rva>0x[0-9a-fA-F]+)")


def effect_index_catalog(path: Path) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for line_number, raw in enumerate(path.read_text(
            encoding="utf-8-sig", errors="strict").splitlines(), 1):
        match = _EFFECT.match(raw)
        if not match:
            continue
        row = match.groupdict()
        result[int(row["rva"], 0)].append({
            "source": str(path.resolve()),
            "source_line": line_number,
            "declaring_class": row["class"],
            "declaring_token": row["token"],
            "type_index": int(row["type"]),
            "type_ordinal": int(row["ordinal"]),
            "method_index": int(row["method_index"]),
            "method_name": row["method"],
            "method_info": row["method_info"],
            "harvest_format": "EFFECT_CALLER_RUNTIME_INDEX",
        })
    return dict(result)


def _merge(into: dict[int, list[dict[str, Any]]],
           source: dict[int, list[dict[str, Any]]]) -> None:
    for rva, rows in source.items():
        for row in rows:
            if row not in into[rva]:
                into[rva].append(row)


def extend(base: dict[str, Any], catalog: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    if base.get("schema") != "uc.ability-dynamic-dispatch-method-join.v1":
        raise ValueError("unsupported base dynamic-dispatch method join")
    targets = []
    newly_matched = 0
    for row in base["targets"]:
        rva = int(row["target_rva"])
        existing = list(row.get("method_candidates", []))
        additions = [candidate for candidate in catalog.get(rva, [])
                     if candidate not in existing]
        candidates = existing + additions
        if not existing and additions:
            newly_matched += 1
        targets.append({
            **row,
            "catalog_status": ("EXACT_METHOD_BODY_MATCH" if candidates
                               else "NO_CATALOG_MATCH"),
            "method_candidates": candidates,
            "additional_method_candidates": additions,
        })
    pairs = []
    target_map = {row["target_rva"]: row for row in targets}
    for pair in base["observed_class_target_pairs"]:
        target = pair.get("target", {})
        if target.get("classification") == "GAME_MODULE_RVA":
            joined = target_map[int(target["rva"])]
            pairs.append({**pair,
                          "catalog_status": joined["catalog_status"],
                          "method_candidates": joined["method_candidates"]})
        else:
            pairs.append(pair)
    exact = sum(bool(row["method_candidates"]) for row in targets)
    return {
        "targets": targets,
        "observed_class_target_pairs": pairs,
        "summary": {
            "observed_game_target_rvas": len(targets),
            "base_exact_catalogued_method_targets": sum(
                bool(row.get("method_candidates")) for row in base["targets"]),
            "newly_catalogued_method_targets": newly_matched,
            "exact_catalogued_method_targets": exact,
            "uncatalogued_method_targets": len(targets) - exact,
            "observed_class_target_pairs": len(pairs),
        },
    }


def analyze(base_path: Path, indirect_join_path: Path, labeled_path: Path,
            effect_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    base = _load(base_path)
    indirect = _load(indirect_join_path)
    if indirect.get("schema") != "uc.ability-executor-indirect-call-join.v1":
        raise ValueError("unsupported Ability indirect-call join")
    method_paths = tuple(Path(row["path"])
                         for row in indirect["sources"]["method_catalogs"])
    for row, path in zip(indirect["sources"]["method_catalogs"], method_paths):
        if file_hash(path) != row["sha256"]:
            raise ValueError(f"method catalog source identity changed: {path}")
    catalog: dict[int, list[dict[str, Any]]] = defaultdict(list)
    _merge(catalog, _merge_catalogs(method_paths))
    _merge(catalog, labeled_runtime_catalog(labeled_path))
    _merge(catalog, effect_index_catalog(effect_path))
    result = {
        "schema": "uc.ability-dynamic-dispatch-authoritative-method-join.v1",
        "sources": {
            "base_method_join": _source(base_path),
            "ability_indirect_call_join": _source(indirect_join_path),
            "labeled_runtime_method_harvest": _source(labeled_path),
            "effect_caller_runtime_index": _source(effect_path),
            "method_catalogs": [_source(path) for path in method_paths],
        },
        "bounded_conclusions": [
            "method identity requires an exact target-RVA match in a preserved runtime harvest",
            "runtime receiver class and harvested declaring class remain separate evidence",
            "unmatched targets remain unresolved and receive no synthesized name",
        ],
        **extend(base, dict(catalog)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(result))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_method_join", type=Path)
    parser.add_argument("ability_indirect_call_join", type=Path)
    parser.add_argument("labeled_runtime_method_harvest", type=Path)
    parser.add_argument("effect_caller_runtime_index", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.base_method_join, args.ability_indirect_call_join,
                         args.labeled_runtime_method_harvest,
                         args.effect_caller_runtime_index, args.output)
    except Exception as error:
        write_failure(args.output, "ability_dynamic_dispatch_authoritative_extend", error, {
            "base_method_join": str(args.base_method_join),
            "ability_indirect_call_join": str(args.ability_indirect_call_join),
            "labeled_runtime_method_harvest": str(args.labeled_runtime_method_harvest),
            "effect_caller_runtime_index": str(args.effect_caller_runtime_index),
        })
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
