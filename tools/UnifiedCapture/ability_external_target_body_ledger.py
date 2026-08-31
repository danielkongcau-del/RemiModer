"""Build a mechanical body ledger for the Ability dependency frontier.

This tool does not assign semantic names.  It records exact function bytes,
bounded control-flow shape, direct callee relations, and exact catalog joins so
that runtime observation is reserved for identities unavailable from the game
image and harvested metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from ability_executor_dependency_frontier import _merge_catalogs
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_FRONTIER = (
    ROOT / "extracted/analysis/ability-executor-dependency-frontier-20260831-v5/"
    "ability-executor-dependency-frontier.json"
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _instruction_shape(ins: dict[str, Any], begin: int, end: int) -> str:
    operands = ins["operands"]
    target = ins.get("direct_target_rva")
    if target is not None:
        location = "local" if begin <= int(target) < end else "external"
        operands = f"<{location}-direct-target>"
    else:
        operands = re.sub(r"\[rip\s*[+-]\s*0x[0-9a-f]+\]", "[rip+disp]", operands)
    return f"{ins['mnemonic']} {operands}".rstrip()


def _mechanical_body_class(instructions: list[dict[str, Any]], decoded_complete: bool) -> str:
    if not decoded_complete:
        return "INCOMPLETE_LINEAR_DECODE"
    if not instructions:
        return "EMPTY_PDATA_RANGE"
    calls = [row for row in instructions if "call" in row.get("groups", [])]
    direct_calls = [row for row in calls if row.get("direct_target_rva") is not None]
    indirect_calls = [row for row in calls if row.get("direct_target_rva") is None]
    traps = {"int3", "ud2", "hlt"}
    if (len(instructions) == 3 and instructions[0]["mnemonic"] == "sub"
            and len(direct_calls) == 1 and instructions[-1]["mnemonic"] in traps):
        return "DIRECT_CALL_THEN_TRAP_STUB"
    if len(instructions) <= 3 and instructions[-1]["mnemonic"] == "jmp":
        return "TAIL_TRANSFER_STUB"
    if not calls:
        return "CALL_FREE_BODY"
    if len(direct_calls) == 1 and not indirect_calls:
        return "SINGLE_DIRECT_CALL_BODY"
    return "MULTI_CALL_BODY"


def build(frontier_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    frontier = _load(frontier_path)
    if frontier.get("schema") != "uc.ability-executor-dependency-frontier.v1":
        raise ValueError("unsupported Ability dependency frontier")
    game_source = frontier["sources"]["game_module"]
    game_path = Path(game_source["path"])
    if file_hash(game_path) != game_source["sha256"]:
        raise ValueError("GameAssembly source identity changed")
    catalog_paths = tuple(Path(row["path"]) for row in frontier["sources"]["method_catalogs"])
    for row, path in zip(frontier["sources"]["method_catalogs"], catalog_paths):
        if file_hash(path) != row["sha256"]:
            raise ValueError(f"method catalog source identity changed: {path}")
    catalogs = _merge_catalogs(catalog_paths)
    pe = NativePE(game_path)
    frontier_targets = {int(row["target_rva"]) for row in frontier["direct_targets"]}

    body_rows: list[dict[str, Any]] = []
    body_classes: Counter[str] = Counter()
    unidentified_body_classes: Counter[str] = Counter()
    structural_clusters: dict[str, list[int]] = defaultdict(list)
    nested_catalog_joins = 0
    nested_frontier_edges = 0
    unidentified_callsites = 0
    unidentified_callsites_in_trap_stubs = 0

    for target in frontier["direct_targets"]:
        target_rva = int(target["target_rva"])
        function = pe.by_start.get(target_rva)
        source_identified = bool(target.get("source_identities") or target.get("source_annotations"))
        if function is None:
            body_rows.append({
                "target_rva": target_rva,
                "callsite_count": target["callsite_count"],
                "source_identified_or_annotated": source_identified,
                "boundary": target["native_shape"]["boundary"],
                "mechanical_body_class": "NO_EXACT_PDATA_ENTRY",
            })
            body_classes["NO_EXACT_PDATA_ENTRY"] += 1
            if not source_identified:
                unidentified_body_classes["NO_EXACT_PDATA_ENTRY"] += 1
                unidentified_callsites += int(target["callsite_count"])
            continue

        decoded = pe.decode(function)
        instructions = decoded["instructions"]
        body_class = _mechanical_body_class(
            instructions, decoded["all_declared_bytes_decoded"])
        body_classes[body_class] += 1
        if not source_identified:
            unidentified_body_classes[body_class] += 1
            unidentified_callsites += int(target["callsite_count"])
            if body_class == "DIRECT_CALL_THEN_TRAP_STUB":
                unidentified_callsites_in_trap_stubs += int(target["callsite_count"])

        signature_text = "\n".join(
            _instruction_shape(row, function.begin, function.end) for row in instructions)
        signature_hash = hashlib.sha256(signature_text.encode("utf-8")).hexdigest()
        structural_clusters[signature_hash].append(target_rva)
        direct_callees = []
        for instruction in instructions:
            if "call" not in instruction.get("groups", []):
                continue
            callee = instruction.get("direct_target_rva")
            if callee is None:
                continue
            callee = int(callee)
            identities = catalogs.get(callee, [])
            if identities:
                nested_catalog_joins += 1
            in_frontier = callee in frontier_targets
            if in_frontier:
                nested_frontier_edges += 1
            direct_callees.append({
                "site_rva": instruction["rva"],
                "target_rva": callee,
                "target_in_dependency_frontier": in_frontier,
                "source_identities": identities,
            })
        cfg = pe.cfg(function)
        raw = pe.bytes_at(function.begin, function.end - function.begin)
        body_rows.append({
            "target_rva": target_rva,
            "callsite_count": target["callsite_count"],
            "caller_type_count": target["caller_type_count"],
            "source_identified_or_annotated": source_identified,
            "mechanical_body_class": body_class,
            "begin_rva": function.begin,
            "end_rva": function.end,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "structural_signature_sha256": signature_hash,
            "linear_decode_complete": decoded["all_declared_bytes_decoded"],
            "instruction_count": len(instructions),
            "reachable_instruction_count": len(cfg["reachable_instruction_rvas"]),
            "cfg_terminals": cfg["terminals"],
            "direct_callees": direct_callees,
            "indirect_call_count": sum(
                "call" in row.get("groups", []) and row.get("direct_target_rva") is None
                for row in instructions),
        })

    clusters = [{
        "structural_signature_sha256": digest,
        "target_count": len(targets),
        "target_rvas": sorted(targets),
    } for digest, targets in structural_clusters.items() if len(targets) > 1]
    clusters.sort(key=lambda row: (-row["target_count"], row["target_rvas"][0]))
    body_rows.sort(key=lambda row: (-row["callsite_count"], row["target_rva"]))

    summary = {
        "targets": len(body_rows),
        "exact_pdata_bodies": sum(row["mechanical_body_class"] != "NO_EXACT_PDATA_ENTRY"
                                  for row in body_rows),
        "source_identified_or_annotated_targets": sum(
            row["source_identified_or_annotated"] for row in body_rows),
        "unidentified_targets": sum(
            not row["source_identified_or_annotated"] for row in body_rows),
        "unidentified_callsites": unidentified_callsites,
        "unidentified_callsites_in_direct_call_then_trap_stubs":
            unidentified_callsites_in_trap_stubs,
        "body_class_counts": dict(sorted(body_classes.items())),
        "unidentified_body_class_counts": dict(sorted(unidentified_body_classes.items())),
        "multi_target_structural_clusters": len(clusters),
        "nested_direct_calls_with_catalog_identity": nested_catalog_joins,
        "nested_direct_edges_to_frontier_targets": nested_frontier_edges,
    }
    artifact = {
        "schema": "uc.ability-external-target-body-ledger.v1",
        "sources": {
            "dependency_frontier": _source(frontier_path),
            "game_module": _source(game_path),
            "method_catalogs": [_source(path) for path in catalog_paths],
        },
        "summary": summary,
        "bounded_conclusions": [
            "body classes describe native instruction shape only and are not semantic method names",
            "a call-then-trap shape is not promoted to an exception or error semantic without independent identity evidence",
            "nested catalog joins are exact RVA matches; structural signatures never create semantic identity",
            "control-flow reachability is mechanical within the exact PDATA range and does not prove runtime branch selection",
        ],
        "runtime_needed_now": False,
        "multi_target_structural_clusters": clusters,
        "targets": body_rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-external-target-body-ledger.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-external-target-body-ledger-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.frontier.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_external_target_body_ledger", error, {
            "frontier": str(args.frontier),
        })
        raise


if __name__ == "__main__":
    run_main(main)
