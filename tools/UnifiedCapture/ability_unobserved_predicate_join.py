"""Join unobserved branch inputs to harvested field-offset candidates without guessing identity."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


MEMORY = re.compile(r"\[([a-z0-9]+) \+ (0x[0-9a-f]+)\]")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _memory_accesses(window: list[dict[str, Any]], field_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_offset: dict[int, list[dict[str, Any]]] = {}
    for field in field_rows:
        by_offset.setdefault(int(field["offset"], 0), []).append({
            "class": field["class"], "field": field["field"],
            "materialized_class": field["materializedClass"],
            "offset": int(field["offset"], 0), "token": field["token"],
        })
    rows = []
    for instruction in window:
        for match in MEMORY.finditer(instruction["operands"]):
            base = match.group(1)
            offset = int(match.group(2), 0)
            rows.append({
                "rva": int(instruction["rva"]), "mnemonic": instruction["mnemonic"],
                "operands": instruction["operands"], "base_register": base,
                "offset": offset,
                "field_candidates": [] if base in ("rsp", "rbp", "rip") else by_offset.get(offset, []),
                "base_object_identity_proven": False,
            })
    return rows


def _predicate_shape(branch: dict[str, Any]) -> str:
    window = branch.get("preceding_instruction_window", [])
    if not window:
        return "NO_PRECEDING_INSTRUCTION_WINDOW"
    prior = window[-1]
    operands = prior["operands"]
    if prior["mnemonic"] == "test":
        parts = [part.strip() for part in operands.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            return "REGISTER_ZERO_TEST"
    if prior["mnemonic"] == "cmp" and "ptr [rip" in operands and operands.endswith(", 0"):
        return "RIP_RELATIVE_MEMORY_COMPARE_ZERO"
    if prior["mnemonic"] == "cmp" and "ptr [" in operands:
        return "MEMORY_COMPARE"
    return "OTHER_EXACT_MACHINE_PREDICATE"


def build(branch_path: Path, coverage_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    branch_ledger = _load(branch_path)
    coverage = _load(coverage_path)
    if branch_ledger.get("schema") != "uc.ability-unobserved-branch-ledger.v1":
        raise ValueError("unsupported unobserved branch ledger")
    if coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported Ability coverage ledger")
    coverage_by_type = {row["serialized_type"]: row for row in coverage["types"]}
    rows = []
    selection_counts: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()
    for site in branch_ledger["sites"]:
        sensitive = {int(row["branch_rva"]): row for row in site["outcome_sensitive_branches"]}
        if site["gating_conditional_branches"]:
            candidates = [sensitive[int(row["branch_rva"])]
                          for row in site["gating_conditional_branches"]]
            selected = min(candidates, key=lambda row: (
                row["shortest_instruction_distance_to_callsite"], row["branch_rva"]))
            selection = "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE"
        else:
            before = [row for row in site["outcome_sensitive_branches"]
                      if int(row["branch_rva"]) < int(site["site_rva"])]
            if not before:
                raise ValueError(f"site has no preceding outcome-sensitive branch: {site['site_rva']:#x}")
            selected = min(before, key=lambda row: (
                row["shortest_instruction_distance_to_callsite"], -row["branch_rva"]))
            selection = "NEAREST_PRECEDING_NON_DOMINATING_OUTCOME_SENSITIVE_BRANCH"
        type_row = coverage_by_type[site["caller_type"]]
        fields = [{**field, "field_scope": "executor"} for field in type_row["executor_fields"]]
        fields += [{**field, "field_scope": "config"} for field in type_row["config_fields"]]
        accesses = _memory_accesses(selected["preceding_instruction_window"], fields)
        shape = _predicate_shape(selected)
        selection_counts[selection] += 1
        shape_counts[shape] += 1
        rows.append({
            "point": site["point"], "site_rva": int(site["site_rva"]),
            "caller_type": site["caller_type"], "caller_method": site["caller_method"],
            "selection_basis": selection,
            "selected_branch": selected,
            "predicate_machine_shape": shape,
            "memory_access_chain": accesses,
            "field_candidate_accesses": sum(bool(row["field_candidates"]) for row in accesses),
            "exact_field_identity_assigned": False,
            "semantic_gameplay_predicate_assigned": False,
        })
    summary = {
        "sites": len(rows),
        "selection_counts": dict(sorted(selection_counts.items())),
        "predicate_shape_counts": dict(sorted(shape_counts.items())),
        "sites_with_harvested_field_offset_candidates": sum(
            row["field_candidate_accesses"] > 0 for row in rows),
        "exact_field_identities_assigned": 0,
        "semantic_gameplay_predicates_assigned": 0,
    }
    artifact = {
        "schema": "uc.ability-unobserved-predicate-join.v1",
        "sources": {"branch_ledger": _source(branch_path),
                    "ability_coverage": _source(coverage_path)},
        "summary": summary,
        "bounded_conclusions": [
            "selected branches and memory offsets are exact machine-code evidence",
            "field rows are candidates joined by numeric offset only because the base object identity is not independently proven",
            "RIP-relative route guards are not promoted to gameplay conditions",
            "no source-level condition, player action, or serialized-field value is assigned by this artifact",
        ],
        "runtime_needed_now": False,
        "sites": rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-unobserved-predicate-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-unobserved-predicate-join-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--branch-ledger", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.branch_ledger.resolve(), args.coverage.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_predicate_join", error,
                      {"branch_ledger": str(args.branch_ledger),
                       "coverage": str(args.coverage)})
        raise


if __name__ == "__main__":
    run_main(main)
