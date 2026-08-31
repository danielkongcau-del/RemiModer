"""Prove selected branch object bases from x64 this aliases and harvested field layouts."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


MEMORY = re.compile(r"\[([a-z0-9]+) \+ (0x[0-9a-f]+)\]")
MOV_REG = re.compile(r"([a-z0-9]+), ([a-z0-9]+)$")
MOV_LOAD = re.compile(r"([a-z0-9]+), (?:byte|word|dword|qword) ptr \[([a-z0-9]+) \+ (0x[0-9a-f]+)\]")
NONVOLATILE = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
ALIASES = {
    "rax": {"rax", "eax", "ax", "al", "ah"}, "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
    "rcx": {"rcx", "ecx", "cx", "cl", "ch"}, "rdx": {"rdx", "edx", "dx", "dl", "dh"},
    "rsi": {"rsi", "esi", "si", "sil"}, "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"}, "rsp": {"rsp", "esp", "sp", "spl"},
    **{f"r{i}": {f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"} for i in range(8, 16)},
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _canonical_register(name: str) -> str | None:
    for canonical_name, names in ALIASES.items():
        if name in names:
            return canonical_name
    return None


def _stable_this_aliases(instructions: list[dict[str, Any]], stop_rva: int) -> dict[str, int]:
    candidates: dict[str, int] = {}
    first_control = next((row["rva"] for row in instructions
                          if "call" in row["groups"] or "jump" in row["groups"]), stop_rva)
    for row in instructions:
        if row["rva"] >= first_control:
            break
        match = MOV_REG.fullmatch(row["operands"]) if row["mnemonic"] == "mov" else None
        if match and match.group(2) == "rcx" and match.group(1) in NONVOLATILE:
            candidates[match.group(1)] = row["rva"]
    stable = {}
    for register, origin in candidates.items():
        aliases = ALIASES[register]
        overwritten = any(row["rva"] > origin and row["rva"] < stop_rva
                          and aliases.intersection(row["regs_write"])
                          for row in instructions)
        if not overwritten:
            stable[register] = origin
    return stable


def _analyze_window(window: list[dict[str, Any]], stable_this: dict[str, int],
                    this_class: str, fields: dict[tuple[str, int], list[dict[str, Any]]]) -> dict[str, Any]:
    provenance = {register: {"class": this_class, "kind": "THIS_ALIAS",
                             "origin_rva": origin}
                  for register, origin in stable_this.items()}
    accesses = []
    for row in window:
        if "call" in row.get("groups", []):
            for register in VOLATILE:
                provenance.pop(register, None)
        load = MOV_LOAD.fullmatch(row["operands"]) if row["mnemonic"] == "mov" else None
        if load:
            destination = _canonical_register(load.group(1))
            base = _canonical_register(load.group(2))
            offset = int(load.group(3), 0)
            base_provenance = provenance.get(base or "")
            exact_fields = (fields.get((base_provenance["class"], offset), [])
                            if base_provenance else [])
            exact = exact_fields[0] if len(exact_fields) == 1 else None
            accesses.append({
                "rva": row["rva"], "operands": row["operands"],
                "base_register": base, "base_provenance": base_provenance,
                "offset": offset, "exact_field": exact,
            })
            if destination:
                if exact and exact["materializedClass"]:
                    provenance[destination] = {
                        "class": exact["materializedClass"], "kind": "EXACT_FIELD_LOAD",
                        "origin_rva": row["rva"], "field": exact,
                    }
                else:
                    provenance.pop(destination, None)
            continue
        move = MOV_REG.fullmatch(row["operands"]) if row["mnemonic"] == "mov" else None
        if move:
            destination = _canonical_register(move.group(1))
            source = _canonical_register(move.group(2))
            if destination:
                if source in provenance:
                    provenance[destination] = provenance[source]
                else:
                    provenance.pop(destination, None)
        for match in MEMORY.finditer(row["operands"]):
            base = _canonical_register(match.group(1))
            offset = int(match.group(2), 0)
            base_provenance = provenance.get(base or "")
            exact_fields = (fields.get((base_provenance["class"], offset), [])
                            if base_provenance else [])
            accesses.append({
                "rva": row["rva"], "operands": row["operands"],
                "base_register": base, "base_provenance": base_provenance,
                "offset": offset,
                "exact_field": exact_fields[0] if len(exact_fields) == 1 else None,
            })
    prior = window[-1]
    tested = None
    if prior["mnemonic"] == "test":
        parts = [part.strip() for part in prior["operands"].split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            tested = provenance.get(_canonical_register(parts[0]) or "")
    return {"accesses": accesses, "selected_tested_value_provenance": tested}


def build(predicate_path: Path, coverage_path: Path, game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    predicate = _load(predicate_path)
    coverage = _load(coverage_path)
    if predicate.get("schema") != "uc.ability-unobserved-predicate-join.v1":
        raise ValueError("unsupported predicate join")
    if coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported coverage ledger")
    by_type = {row["serialized_type"]: row for row in coverage["types"]}
    fields: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for type_row in coverage["types"]:
        for field in type_row["executor_fields"] + type_row["config_fields"]:
            key = (field["class"], int(field["offset"], 0))
            candidate = {key: field[key] for key in (
                "class", "field", "materializedClass", "offset", "token")}
            if candidate not in fields.setdefault(key, []):
                fields[key].append(candidate)
    image = NativePE(game_path)
    rows = []
    for site in predicate["sites"]:
        type_row = by_type[site["caller_type"]]
        this_class = type_row["executor_class"] or type_row["config_class"]
        function = image.containing(int(site["site_rva"]))
        if function is None:
            raise ValueError(f"site lacks PDATA owner: {site['site_rva']:#x}")
        decoded = image.decode(function)
        if not decoded["all_declared_bytes_decoded"]:
            raise ValueError(f"site owner is not fully decoded: {site['site_rva']:#x}")
        branch_rva = int(site["selected_branch"]["branch_rva"])
        stable = _stable_this_aliases(decoded["instructions"], branch_rva)
        analyzed = _analyze_window(site["selected_branch"]["preceding_instruction_window"],
                                   stable, this_class, fields)
        rows.append({
            "point": site["point"], "site_rva": int(site["site_rva"]),
            "caller_type": site["caller_type"], "caller_method": site["caller_method"],
            "method_this_class": this_class,
            "pdata_begin_rva": function.begin, "pdata_end_rva": function.end,
            "stable_nonvolatile_this_aliases": stable,
            **analyzed,
            "semantic_gameplay_predicate_assigned": False,
        })
    summary = {
        "sites": len(rows),
        "sites_with_stable_nonvolatile_this_alias": sum(
            bool(row["stable_nonvolatile_this_aliases"]) for row in rows),
        "sites_with_exact_field_access_in_selected_window": sum(
            any(access["exact_field"] for access in row["accesses"]) for row in rows),
        "selected_test_values_with_exact_object_provenance": sum(
            bool(row["selected_tested_value_provenance"]
                 and row["selected_tested_value_provenance"]["kind"] == "EXACT_FIELD_LOAD")
            for row in rows),
        "semantic_gameplay_predicates_assigned": 0,
    }
    artifact = {
        "schema": "uc.ability-unobserved-base-identity-join.v1",
        "sources": {"predicate_join": _source(predicate_path),
                    "ability_coverage": _source(coverage_path),
                    "game_module": _source(game_path)},
        "summary": summary,
        "bounded_conclusions": [
            "a this alias is accepted only when copied from entry RCX before the first control transfer into a nonvolatile x64 register and never explicitly overwritten before the selected branch",
            "calls preserve accepted aliases under the Windows x64 nonvolatile-register ABI",
            "an exact field requires a proven base class and exactly one harvested field at that class and offset",
            "no field name, object identity, or gameplay predicate is inferred from offset alone",
        ],
        "runtime_needed_now": False,
        "sites": rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-unobserved-base-identity-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-unobserved-base-identity-join-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predicate-join", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.predicate_join.resolve(), args.coverage.resolve(),
                     args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_base_identity_join", error,
                      {"predicate_join": str(args.predicate_join),
                       "coverage": str(args.coverage), "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
