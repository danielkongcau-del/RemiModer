"""Rank the native dependency frontier of the 188-type Ability ledger.

The output is a work queue, not semantic decompilation: exact direct targets,
indirect callsites, broad harvested method identities, and PDATA shapes remain
separate evidence fields.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_LEDGER = ROOT / "extracted/analysis/ability-executor-coverage-ledger-20260831-v1/ability-executor-coverage-ledger.json"
DEFAULT_METADATA = ROOT / "extracted/trigger-metadata-slots-20260827.txt"
DEFAULT_CATALOGS = (
    ROOT / "extracted/ability-binary-runtime-methods.txt",
    ROOT / "extracted/ability-action-subclass-methods.txt",
    ROOT / "extracted/ability-config-node-subclass-methods.txt",
    ROOT / "extracted/ability-config-node-base-methods.txt",
    ROOT / "extracted/ability-config-family-base-methods.txt",
    ROOT / "extracted/ability-component-methods.txt",
    ROOT / "extracted/ability-type-resolver-methods.txt",
    ROOT / "extracted/remielle-ability-config-type-methods.txt",
    ROOT / "extracted/remielle-mixin-executor-methods.txt",
    ROOT / "extracted/behavior-ecs-candidates-20260827.txt",
    ROOT / "extracted/behavior-task-executors-20260827-v2.txt",
    ROOT / "extracted/unity-object-runtime-method-signatures-p0i3.txt",
    ROOT / "extracted/component-runtime-methods-20260831.txt",
    ROOT / "extracted/gameobject-runtime-methods-20260831.txt",
    ROOT / "extracted/jobhandle-runtime-methods-20260831.txt",
    ROOT / "extracted/quaternion-runtime-methods-20260831.txt",
    ROOT / "extracted/transform-runtime-methods-20260831.txt",
    ROOT / "extracted/vector3-runtime-methods-20260831.txt",
    ROOT / "extracted/ability-slot-owner-runtime-methods-20260831-v1.txt",
    ROOT / "extracted/ability-direct-owner-runtime-methods-20260831-v1.txt",
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _catalog(path: Path) -> dict[int, list[dict[str, Any]]]:
    classes: dict[str, dict[str, Any]] = {}
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        fields = line.split("|")
        if len(fields) >= 5 and fields[0] == "CLASS" and "=" not in fields[1]:
            classes[fields[1]] = {"namespace": fields[3], "class": fields[4]}
        elif len(fields) >= 5 and fields[0] == "METHOD" and "=" not in fields[1]:
            try:
                rva = int(fields[4], 0)
            except ValueError:
                continue
            owner = classes.get(fields[1], {"namespace": None, "class": fields[1]})
            result[rva].append({
                **owner, "method": fields[3], "line": line_number,
                "source": str(path.resolve()),
            })
        elif fields and fields[0] == "CLASS":
            values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
            if "label" in values and "name" in values:
                classes[values["label"]] = {"namespace": values.get("namespace"), "class": values["name"]}
        elif fields and fields[0] == "METHOD":
            values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
            if not {"label", "name", "rva"} <= values.keys():
                continue
            try:
                rva = int(values["rva"], 0)
            except ValueError:
                continue
            owner = classes.get(values["label"], {"namespace": None, "class": values["label"]})
            result[rva].append({
                **owner, "method": values["name"], "line": line_number,
                "source": str(path.resolve()),
            })
    return result


def _merge_catalogs(paths: tuple[Path, ...]) -> dict[int, list[dict[str, Any]]]:
    merged: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for path in paths:
        for rva, rows in _catalog(path).items():
            for row in rows:
                key = (row.get("namespace"), row.get("class"), row.get("method"), row.get("source"), row.get("line"))
                if not any((old.get("namespace"), old.get("class"), old.get("method"), old.get("source"), old.get("line")) == key
                           for old in merged[rva]):
                    merged[rva].append(row)
    return merged


def _factory_annotations(ledger: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in ledger.get("types", []):
        factory = row.get("factory") or {}
        for field, value in factory.items():
            if not field.lower().endswith("rva") or value is None:
                continue
            numeric = int(value, 0) if isinstance(value, str) else int(value)
            result[numeric].append({
                "kind": "stored_factory_rva_field",
                "field": field,
                "serialized_type": row["serialized_type"],
            })
    return result


def _metadata_annotation(path: Path) -> tuple[int, dict[str, Any]] | None:
    first = path.read_text(encoding="utf-8-sig").splitlines()[0]
    match = re.search(r"\binit-rva=(0x[0-9a-fA-F]+)", first)
    if not match:
        return None
    return int(match.group(1), 0), {
        "kind": "source_declared_metadata_init_rva", "line": 1,
        "source": str(path.resolve()),
    }


def _stratum(type_count: int, identities: list[dict[str, Any]], annotations: list[dict[str, Any]]) -> str:
    if identities or annotations:
        return "SOURCE_IDENTIFIED_OR_ANNOTATED"
    if type_count >= 150:
        return "UBIQUITOUS_ACROSS_SELECTED_TYPES"
    if type_count >= 4:
        return "SHARED_UNIDENTIFIED"
    return "NARROW_UNIDENTIFIED"


def build(ledger_path: Path, catalog_paths: tuple[Path, ...], metadata_path: Path,
          out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    ledger = _load(ledger_path)
    if ledger.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported Ability executor ledger")
    if ledger.get("summary", {}).get("types") != 188:
        raise ValueError("Ability executor ledger does not contain 188 types")
    for path in catalog_paths + (metadata_path,):
        if not path.is_file():
            raise FileNotFoundError(path)
    game_source = ledger["sources"]["game_module"]
    game_path = Path(game_source["path"])
    if file_hash(game_path) != game_source["sha256"]:
        raise ValueError("GameAssembly source identity changed")
    pe = NativePE(game_path)
    catalog = _merge_catalogs(catalog_paths)
    annotations = _factory_annotations(ledger)
    metadata = _metadata_annotation(metadata_path)
    if metadata:
        annotations[metadata[0]].append(metadata[1])

    direct: dict[int, dict[str, Any]] = {}
    indirect = []
    for type_row in ledger["types"]:
        type_name = type_row["serialized_type"]
        occurrences = int(type_row.get("occurrences") or 0)
        for method in type_row.get("methods", []):
            body = method.get("body_decode")
            if not body:
                continue
            for call in body.get("direct_calls", []):
                if call.get("target_identity_status") == "CATALOG_MATCH":
                    continue
                target = int(call["target_rva"])
                row = direct.setdefault(target, {
                    "target_rva": target, "callsites": [], "caller_types": set(),
                    "caller_methods": set(), "asset_occurrence_weight": 0,
                })
                row["callsites"].append({
                    "site_rva": call["site_rva"], "caller_type": type_name,
                    "caller_method": method["name"], "caller_role": method.get("role"),
                })
                row["caller_types"].add(type_name)
                row["caller_methods"].add((type_name, method["name"]))
                row["asset_occurrence_weight"] += occurrences
            for call in body.get("indirect_calls", []):
                indirect.append({
                    "site_rva": call["site_rva"], "operands": call["operands"],
                    "bytes": call["bytes"], "caller_type": type_name,
                    "caller_method": method["name"], "caller_role": method.get("role"),
                    "caller_type_occurrences": occurrences,
                })
    targets = []
    for target, row in direct.items():
        identities = catalog.get(target, [])
        target_annotations = annotations.get(target, [])
        function = pe.by_start.get(target)
        owner = pe.containing(target)
        shape = None
        if function:
            decoded = pe.decode(function)
            shape = {
                "boundary": "EXACT_PDATA_ENTRY", "begin_rva": function.begin,
                "end_rva": function.end, "all_declared_bytes_decoded": decoded["all_declared_bytes_decoded"],
                "instruction_count": len(decoded["instructions"]),
                "direct_call_count": sum("call" in ins.get("groups", []) and ins.get("direct_target_rva") is not None
                                         for ins in decoded["instructions"]),
                "indirect_call_count": sum("call" in ins.get("groups", []) and ins.get("direct_target_rva") is None
                                           for ins in decoded["instructions"]),
            }
        elif owner:
            shape = {"boundary": "INSIDE_PDATA_FUNCTION", "begin_rva": owner.begin, "end_rva": owner.end}
        else:
            shape = {"boundary": "NO_PDATA_OWNER"}
        caller_types = sorted(row["caller_types"])
        item = {
            "target_rva": target,
            "callsite_count": len(row["callsites"]),
            "caller_type_count": len(caller_types),
            "caller_method_count": len(row["caller_methods"]),
            "asset_occurrence_weight": row["asset_occurrence_weight"],
            "caller_types": caller_types,
            "source_identities": identities,
            "source_annotations": target_annotations,
            "stratum": _stratum(len(caller_types), identities, target_annotations),
            "native_shape": shape,
            "callsites": sorted(row["callsites"], key=lambda value: (value["caller_type"], value["site_rva"])),
        }
        targets.append(item)
    targets.sort(key=lambda row: (
        0 if row["stratum"] == "SOURCE_IDENTIFIED_OR_ANNOTATED" else 1,
        -row["asset_occurrence_weight"], -row["callsite_count"], row["target_rva"]
    ))
    indirect.sort(key=lambda row: (-row["caller_type_occurrences"], row["caller_type"], row["site_rva"]))
    strata = Counter(row["stratum"] for row in targets)
    boundaries = Counter(row["native_shape"]["boundary"] for row in targets)
    artifact = {
        "schema": "uc.ability-executor-dependency-frontier.v1",
        "sources": {
            "ability_executor_coverage": _source(ledger_path),
            "game_module": _source(game_path),
            "metadata_slots": _source(metadata_path),
            "method_catalogs": [_source(path) for path in catalog_paths],
        },
        "summary": {
            "external_direct_calls": sum(row["callsite_count"] for row in targets),
            "unique_external_direct_targets": len(targets),
            "indirect_callsites": len(indirect),
            "source_identified_or_annotated_targets": strata["SOURCE_IDENTIFIED_OR_ANNOTATED"],
            "stratum_counts": dict(sorted(strata.items())),
            "target_boundary_counts": dict(sorted(boundaries.items())),
        },
        "bounded_conclusions": [
            "all direct target and callsite relations are decoded from the selected game image",
            "source identities are exact RVA joins to harvested game runtime method tables",
            "frequency and asset occurrence weight are ranking signals, not semantic importance",
            "ubiquity is not promoted to a framework semantic name",
            "indirect call operands are retained without guessed targets",
        ],
        "runtime_needed_now": False,
        "direct_targets": targets,
        "indirect_callsites": indirect,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-executor-dependency-frontier.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-executor-dependency-frontier-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": artifact["summary"], "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--catalog", action="append", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    catalogs = tuple(path.resolve() for path in (args.catalog or DEFAULT_CATALOGS))
    try:
        return build(args.ledger.resolve(), catalogs, args.metadata.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_executor_dependency_frontier", error, {
            "ledger": str(args.ledger), "metadata": str(args.metadata),
            "catalogs": [str(path) for path in catalogs],
        })
        raise


if __name__ == "__main__":
    run_main(main)
