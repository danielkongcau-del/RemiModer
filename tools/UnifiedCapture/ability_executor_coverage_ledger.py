"""Build the bounded, per-type native executor coverage ledger for Remielle.

This is a mechanical offline join.  It records what the selected game image,
the typed Ability inventory, and preserved runtime reports actually prove.  A
decoded PDATA body is not promoted to semantic understanding or execution.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_INVENTORY = ROOT / "extracted/analysis/controller-acquisition-audit-v2/inventory.json"
DEFAULT_TYPE_LEDGER = HERE / "plans/v6/type-ledger.json"
DEFAULT_ROLE_GAP = ROOT / "extracted/analysis/controller-role-aware-gap-20260830-v3/controller-role-aware-gap.json"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _game_source(type_ledger: dict[str, Any]) -> tuple[Path, str]:
    matches = []
    for row in type_ledger.get("sources", {}).values():
        path = Path(row["path"])
        if path.name.lower() == "gameassembly.dll":
            matches.append((path, row["sha256"]))
    if len(matches) != 1:
        raise ValueError(f"expected one GameAssembly source, got {len(matches)}")
    return matches[0]


def _dispatch_shape(raw: dict[str, Any]) -> str:
    dispatch = raw.get("nativeIdentityAndDispatch", {}).get("dispatch")
    if not dispatch:
        return "NO_DISPATCH_JOIN"
    keys = set(dispatch)
    if {"wrapper", "nativeImplementation"} <= keys:
        return "ACTION_WRAPPER_AND_NATIVE_IMPLEMENTATION"
    if "executorClass" in keys:
        return "EXECUTOR_CLASS_WITH_FACTORY"
    if "operationalMethods" in keys:
        return "OPERATIONAL_METHODS_ONLY"
    return "OTHER_SOURCE_DISPATCH_SHAPE"


def _runtime_rows(role_gap: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in role_gap.get("ability_action_entries", []):
        type_name = row["serialized_type"]
        roles = {}
        for key, value in row.get("roles", {}).items():
            if isinstance(value, dict):
                roles[key] = {
                    field: value.get(field)
                    for field in ("method", "rva", "point", "status", "capture_policy")
                    if value.get(field) is not None
                }
        result[type_name] = {
            "dispatch_role_status": row.get("dispatch_role_status"),
            "roles": roles,
            "capture_policy": row.get("capture_policy"),
        }
    return result


def _method_shape(pe: NativePE, method: dict[str, Any], catalog: dict[int, list[dict[str, str]]]) -> dict[str, Any]:
    rva = int(method["rva"])
    result: dict[str, Any] = {
        "role": method.get("role"),
        "name": method.get("name"),
        "rva": rva,
        "signature_evidence": method.get("signature_evidence", []),
        "declared_function_entry_in_pdata": bool(method.get("function_entry_in_pdata")),
        "native_prefix": method.get("native_prefix"),
    }
    runtime_function = pe.by_start.get(rva)
    if runtime_function is None:
        owner = pe.containing(rva)
        result["boundary_status"] = "NO_INDEPENDENT_PDATA_ENTRY"
        result["containing_pdata_begin_rva"] = owner.begin if owner else None
        result["containing_pdata_end_rva"] = owner.end if owner else None
        result["body_decode"] = None
        return result
    if not method.get("function_entry_in_pdata"):
        raise ValueError(f"{method['type']}.{method['name']} has PDATA entry but source flag is false")
    decoded = pe.decode(runtime_function)
    calls = []
    indirect_calls = []
    for instruction in decoded["instructions"]:
        if "call" not in instruction.get("groups", []):
            continue
        target = instruction.get("direct_target_rva")
        if target is None:
            indirect_calls.append({
                "site_rva": instruction["rva"],
                "bytes": instruction["bytes"],
                "operands": instruction["operands"],
            })
            continue
        identities = catalog.get(target, [])
        calls.append({
            "site_rva": instruction["rva"],
            "target_rva": target,
            "target_identities": identities,
            "target_identity_status": "CATALOG_MATCH" if identities else "OUTSIDE_SELECTED_TYPE_CATALOG",
        })
    result["boundary_status"] = "EXACT_PDATA_ENTRY"
    result["body_decode"] = {
        "begin_rva": runtime_function.begin,
        "end_rva": runtime_function.end,
        "unwind_rva": runtime_function.unwind_rva,
        "all_declared_bytes_decoded": decoded["all_declared_bytes_decoded"],
        "instruction_count": len(decoded["instructions"]),
        "direct_calls": calls,
        "indirect_calls": indirect_calls,
    }
    return result


def build(inventory_path: Path, type_ledger_path: Path, role_gap_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    inventory = _load(inventory_path)
    type_ledger = _load(type_ledger_path)
    role_gap = _load(role_gap_path)
    rows = inventory.get("nativeTypeLedger", [])
    prior_types = {row["type"]: row for row in type_ledger.get("types", [])}
    if len(rows) != 188 or len(prior_types) != 188:
        raise ValueError("the selected authoritative inventories must each contain 188 types")
    if {row["serializedType"] for row in rows} != set(prior_types):
        raise ValueError("inventory/type-ledger type sets differ")
    game_path, expected_game_hash = _game_source(type_ledger)
    if file_hash(game_path) != expected_game_hash:
        raise ValueError("GameAssembly source identity changed")
    pe = NativePE(game_path)

    catalog: dict[int, list[dict[str, str]]] = defaultdict(list)
    for method in type_ledger.get("methods", []):
        catalog[int(method["rva"])].append({
            "type": method["type"], "name": method["name"], "role": method.get("role")
        })
    runtime = _runtime_rows(role_gap)
    results = []
    method_totals = Counter()
    for index, raw in enumerate(rows):
        type_name = raw["serializedType"]
        prior = prior_types[type_name]
        methods = []
        for method in prior.get("methods", []):
            full_method = dict(method)
            full_method["type"] = type_name
            methods.append(_method_shape(pe, full_method, catalog))
        exact = [row for row in methods if row["boundary_status"] == "EXACT_PDATA_ENTRY"]
        no_boundary = [row for row in methods if row["boundary_status"] == "NO_INDEPENDENT_PDATA_ENTRY"]
        decoded = [row for row in exact if row["body_decode"]["all_declared_bytes_decoded"]]
        direct_calls = sum(len(row["body_decode"]["direct_calls"]) for row in exact)
        indirect_calls = sum(len(row["body_decode"]["indirect_calls"]) for row in exact)
        catalog_calls = sum(
            call["target_identity_status"] == "CATALOG_MATCH"
            for row in exact for call in row["body_decode"]["direct_calls"]
        )
        positions = raw.get("positions", [])
        raw_complete = bool(positions) and len(positions) == raw.get("occurrences")
        dispatch_shape = _dispatch_shape(raw)
        if not methods:
            static_status = "NO_METHOD_IDENTITY"
        elif len(decoded) != len(exact):
            static_status = "DECODE_INCOMPLETE"
        elif no_boundary:
            static_status = "BOUNDED_BODIES_PLUS_PDATA_LESS_ENTRIES"
        else:
            static_status = "ALL_CATALOG_METHOD_BODIES_DECODED"
        unresolved = []
        if dispatch_shape == "NO_DISPATCH_JOIN":
            unresolved.append("serialized type has no source-joined dispatch shape")
        if no_boundary:
            unresolved.append("one or more method identities lack independent PDATA boundaries")
        if indirect_calls:
            unresolved.append("one or more native bodies contain indirect callsites")
        if direct_calls != catalog_calls:
            unresolved.append("one or more direct targets lie outside the selected 188-type method catalog")
        unresolved.append("mechanical native decoding does not by itself name all state transitions or external dependencies")
        dynamic = runtime.get(type_name)
        results.append({
            "serialized_type": type_name,
            "inventory_pointer": f"/nativeTypeLedger/{index}",
            "occurrences": raw.get("occurrences"),
            "positions_complete": raw_complete,
            "abilities": sorted({row["ability"] for row in positions}),
            "identity_evidence_kind": raw.get("identityEvidenceKind"),
            "native_role": raw.get("nativeIdentityAndDispatch", {}).get("role"),
            "dispatch_shape": dispatch_shape,
            "config_class": raw.get("nativeIdentityAndDispatch", {}).get("configClass"),
            "executor_class": raw.get("nativeIdentityAndDispatch", {}).get("dispatch", {}).get("executorClass"),
            "config_fields": raw.get("nativeIdentityAndDispatch", {}).get("configFields", []),
            "executor_fields": raw.get("nativeIdentityAndDispatch", {}).get("executorFields", []),
            "factory": raw.get("nativeIdentityAndDispatch", {}).get("dispatch", {}).get("factory"),
            "static_coverage": {
                "status": static_status,
                "method_count": len(methods),
                "exact_pdata_entries": len(exact),
                "pdata_less_entries": len(no_boundary),
                "fully_decoded_pdata_bodies": len(decoded),
                "direct_calls": direct_calls,
                "direct_calls_to_selected_catalog": catalog_calls,
                "indirect_calls": indirect_calls,
            },
            "runtime_coverage": dynamic or {
                "status": "NOT_TYPE_JOINED_BY_SELECTED_RUNTIME_REPORT",
                "bounded_meaning": "absence from this report is not non-execution",
            },
            "methods": methods,
            "unresolved": unresolved,
            "complete_executor_semantics": False,
        })
        method_totals.update({
            "methods": len(methods), "exact_pdata_entries": len(exact),
            "pdata_less_entries": len(no_boundary), "fully_decoded_pdata_bodies": len(decoded),
            "direct_calls": direct_calls, "direct_calls_to_selected_catalog": catalog_calls,
            "indirect_calls": indirect_calls,
        })

    status_counts = Counter(row["static_coverage"]["status"] for row in results)
    dispatch_counts = Counter(row["dispatch_shape"] for row in results)
    artifact = {
        "schema": "uc.ability-executor-coverage-ledger.v1",
        "scope": "188 serialized types in the authoritative Remielle Origin Ability inventory",
        "sources": {
            "inventory": _source(inventory_path),
            "type_ledger": _source(type_ledger_path),
            "role_gap": _source(role_gap_path),
            "game_module": _source(game_path),
        },
        "claims": {
            "per_type_coverage_accounted": True,
            "type_count": len(results),
            "serialized_positions_are_not_runtime_execution": True,
            "pdata_decode_is_not_complete_semantics": True,
            "unknown_targets_are_preserved": True,
            "complete_executor_semantics": False,
            "runtime_needed_now": False,
        },
        "summary": {
            "types": len(results),
            "positions_complete_types": sum(row["positions_complete"] for row in results),
            "dispatch_shape_counts": dict(sorted(dispatch_counts.items())),
            "static_status_counts": dict(sorted(status_counts.items())),
            **dict(method_totals),
            "runtime_role_joined_types": len(runtime),
        },
        "next_work": [
            "prioritize source-relevant unresolved external targets and indirect callsites offline",
            "do not request gameplay merely because a serialized type lacks type-level runtime execution",
            "design runtime capture only for a concrete branch or owner edge that static evidence cannot decide",
        ],
        "types": sorted(results, key=lambda row: row["serialized_type"]),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-executor-coverage-ledger.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-executor-coverage-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": artifact["summary"],
        "complete_executor_semantics": False,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--type-ledger", type=Path, default=DEFAULT_TYPE_LEDGER)
    parser.add_argument("--role-gap", type=Path, default=DEFAULT_ROLE_GAP)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.inventory.resolve(), args.type_ledger.resolve(), args.role_gap.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_executor_coverage_ledger", error, {
            "inventory": str(args.inventory), "type_ledger": str(args.type_ledger),
            "role_gap": str(args.role_gap),
        })
        raise


if __name__ == "__main__":
    run_main(main)
