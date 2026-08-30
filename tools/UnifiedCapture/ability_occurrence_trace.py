"""Resolve inventory positions back to authoritative ability JSON nodes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterator

from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _escape(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def _walk(value: Any, pointer: str = "") -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        if isinstance(value.get("$type"), str):
            yield pointer, value
        for key, child in value.items():
            yield from _walk(child, f"{pointer}/{_escape(str(key))}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{pointer}/{index}")


def _resolve(value: Any, pointer: str) -> Any:
    current = value
    for raw in pointer.split("/")[1:]:
        part = raw.replace("~1", "/").replace("~0", "~")
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def run(inventory_path: Path, abilities_dir: Path, type_name: str, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    inventory = _load(inventory_path)
    row = next((item for item in inventory.get("nativeTypeLedger", [])
                if item.get("serializedType") == type_name), None)
    if row is None:
        raise ValueError(f"type is not present in inventory: {type_name}")

    scanned = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for asset_path in sorted(abilities_dir.glob("*.json")):
        asset = _load(asset_path)
        ability_name = asset.get("AbilityName") or asset_path.stem
        for pointer, node in _walk(asset):
            if node.get("$type") == type_name:
                parent_pointer = pointer.rsplit("/", 1)[0]
                parent = _resolve(asset, parent_pointer) if parent_pointer else asset
                index = int(pointer.rsplit("/", 1)[1]) if isinstance(parent, list) else None
                item = {"ability": ability_name, "json_pointer": pointer,
                        "parent_pointer": parent_pointer, "array_index": index,
                        "node": node, "asset": _source(asset_path)}
                scanned.append(item)
                by_key[(ability_name, pointer)] = item

    declared = []
    for position in row.get("positions", []):
        key = (position["ability"], position["jsonPointer"])
        match = by_key.get(key)
        declared.append({"inventory_position": position, "resolved": match is not None,
                         "resolved_occurrence": match})
    undeclared = [item for item in scanned if (item["ability"], item["json_pointer"])
                  not in {(position["ability"], position["jsonPointer"])
                          for position in row.get("positions", [])}]
    checks = {
        "declared_occurrence_count": len(row.get("positions", [])),
        "scanned_occurrence_count": len(scanned),
        "all_declared_positions_resolved": all(item["resolved"] for item in declared),
        "no_undeclared_scanned_occurrences": not undeclared,
        "inventory_occurrence_count_matches_scan": int(row.get("occurrences", -1)) == len(scanned),
    }
    if not all(checks.values()):
        raise ValueError(f"occurrence trace checks failed: {checks}")
    result = {"schema": "uc.ability-occurrence-trace.v1", "serialized_type": type_name,
        "sources": {"inventory": _source(inventory_path), "abilities_directory": str(abilities_dir)},
        "inventory_identity": {"occurrences": row.get("occurrences"),
            "identity_evidence_kind": row.get("identityEvidenceKind"),
            "identity_evidence_source": row.get("identityEvidenceSource"),
            "native_identity_and_dispatch": row.get("nativeIdentityAndDispatch")},
        "occurrences": scanned, "declared_positions": declared, "checks": checks,
        "bounded_conclusion": "all inventory positions resolve to matching $type nodes in the selected authoritative ability set",
        "not_proven": ["that the occurrence executed in any runtime session",
                       "the semantic implementation of the action",
                       "that the selected ability set contains every game mode or future asset"],
    }
    output.mkdir(parents=True)
    artifact = output / "ability-occurrence-trace.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.ability-occurrence-trace-report.v1", "artifact": _source(artifact),
              "serialized_type": type_name, **checks}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--abilities-dir", type=Path, required=True)
    parser.add_argument("--type", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.inventory.resolve(), args.abilities_dir.resolve(), args.type, args.out.resolve())
