"""Mechanically identify conditional branches gating unobserved Ability callsites."""
from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _register_family(register: str) -> str:
    aliases = {
        "rax": "a", "eax": "a", "ax": "a", "al": "a",
        "rbx": "b", "ebx": "b", "bx": "b", "bl": "b",
        "rcx": "c", "ecx": "c", "cx": "c", "cl": "c",
        "rdx": "d", "edx": "d", "dx": "d", "dl": "d",
        "rsi": "si", "esi": "si", "si": "si", "sil": "si",
        "rdi": "di", "edi": "di", "di": "di", "dil": "di",
        "rbp": "bp", "ebp": "bp", "bp": "bp", "bpl": "bp",
        "rsp": "sp", "esp": "sp", "sp": "sp", "spl": "sp",
    }
    if register in aliases:
        return aliases[register]
    match = re.fullmatch(r"r(\d+)(?:d|w|b)?", register)
    return f"r{match.group(1)}" if match else register


def _resolve_local_jump_tables(image: NativePE, instructions: list[dict[str, Any]],
                               begin: int, end: int) -> dict[int, list[int]]:
    """Resolve the exact RIP-relative signed-dword table shape used by these bodies."""
    boundaries = {int(row["rva"]) for row in instructions}
    resolved: dict[int, list[int]] = {}
    for index, terminal in enumerate(instructions):
        if terminal["mnemonic"] != "jmp" or not re.fullmatch(r"[a-z0-9]+", terminal["operands"]):
            continue
        target_reg = terminal["operands"]
        base_reg = index_reg = comparison_index_reg = None
        table_rva = maximum = None
        for row in reversed(instructions[max(0, index - 24):index]):
            operands = row["operands"].replace(" ", "")
            if base_reg is None and row["mnemonic"] == "add":
                match = re.fullmatch(rf"{target_reg},([a-z0-9]+)", operands)
                if match:
                    base_reg = match.group(1)
                    continue
            if base_reg is not None and index_reg is None and row["mnemonic"] == "movsxd":
                match = re.fullmatch(
                    rf"{target_reg},dwordptr\[{base_reg}\+([a-z0-9]+)\*4\]", operands)
                if match:
                    index_reg = match.group(1)
                    comparison_index_reg = index_reg
                    continue
            if base_reg is not None and table_rva is None and row["mnemonic"] == "lea":
                match = re.fullmatch(rf"{base_reg},\[rip([+-])0x([0-9a-f]+)\]", operands)
                if match:
                    displacement = int(match.group(2), 16) * (1 if match.group(1) == "+" else -1)
                    table_rva = int(row["rva"]) + int(row["size"]) + displacement
                    continue
            if index_reg is not None and row["mnemonic"] == "mov":
                match = re.fullmatch(r"([a-z0-9]+),([a-z0-9]+)", operands)
                if (match and _register_family(match.group(1)) ==
                        _register_family(index_reg)):
                    comparison_index_reg = match.group(2)
                    continue
            if comparison_index_reg is not None and maximum is None and row["mnemonic"] == "cmp":
                match = re.fullmatch(r"([a-z0-9]+),(0x[0-9a-f]+|[0-9]+)", operands)
                if (match and _register_family(match.group(1)) ==
                        _register_family(comparison_index_reg)):
                    maximum = int(match.group(2), 0)
                    break
        if None in (base_reg, index_reg, table_rva, maximum) or int(maximum) > 1024:
            continue
        try:
            values = struct.unpack("<" + "i" * (int(maximum) + 1),
                                   image.bytes_at(int(table_rva), (int(maximum) + 1) * 4))
        except (ValueError, struct.error):
            continue
        targets = [int(table_rva) + value for value in values]
        if all(begin <= target < end and target in boundaries for target in targets):
            resolved[int(terminal["rva"])] = targets
    return resolved


def _successors(instructions: list[dict[str, Any]], begin: int, end: int,
                resolved_indirect: dict[int, list[int]] | None = None) -> dict[int, set[int]]:
    by_rva = {int(row["rva"]): row for row in instructions}
    resolved_indirect = resolved_indirect or {}
    graph: dict[int, set[int]] = {rva: set() for rva in by_rva}
    for rva, row in by_rva.items():
        following = rva + int(row["size"])
        groups = set(row.get("groups", []))
        mnemonic = row["mnemonic"]
        if mnemonic.startswith("ret") or mnemonic in ("ud2", "int3", "hlt"):
            continue
        if "jump" in groups:
            target = row.get("direct_target_rva")
            if target is not None and begin <= int(target) < end and int(target) in by_rva:
                graph[rva].add(int(target))
            else:
                graph[rva].update(value for value in resolved_indirect.get(rva, [])
                                  if value in by_rva)
            if mnemonic != "jmp" and following in by_rva:
                graph[rva].add(following)
            continue
        if following in by_rva:
            graph[rva].add(following)
    return graph


def _reachable(graph: dict[int, set[int]], start: int) -> set[int]:
    seen: set[int] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in seen or node not in graph:
            continue
        seen.add(node)
        stack.extend(graph[node] - seen)
    return seen


def _dominators(graph: dict[int, set[int]], entry: int) -> dict[int, set[int]]:
    reachable = _reachable(graph, entry)
    predecessors = {node: set() for node in reachable}
    for source, targets in graph.items():
        if source not in reachable:
            continue
        for target in targets:
            if target in reachable:
                predecessors[target].add(source)
    dominators = {node: ({entry} if node == entry else set(reachable)) for node in reachable}
    changed = True
    while changed:
        changed = False
        for node in sorted(reachable - {entry}):
            preds = predecessors[node]
            common = set.intersection(*(dominators[pred] for pred in preds)) if preds else set()
            updated = {node} | common
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    return dominators


def _gating_branches(instructions: list[dict[str, Any]], begin: int, end: int,
                     site_rva: int, resolved_indirect: dict[int, list[int]] | None = None
                     ) -> list[dict[str, Any]]:
    graph = _successors(instructions, begin, end, resolved_indirect)
    dominators = _dominators(graph, begin)
    if site_rva not in dominators:
        raise ValueError(f"callsite is not reachable in mechanical CFG: {site_rva:#x}")
    by_rva = {int(row["rva"]): row for row in instructions}
    rows = []
    for branch_rva in sorted(dominators[site_rva]):
        branch = by_rva[branch_rva]
        if "jump" not in set(branch.get("groups", [])) or branch["mnemonic"] == "jmp":
            continue
        following = branch_rva + int(branch["size"])
        target = branch.get("direct_target_rva")
        if target is None or int(target) not in graph:
            continue
        taken_reaches = site_rva in _reachable(graph, int(target))
        fallthrough_reaches = site_rva in _reachable(graph, following)
        if taken_reaches == fallthrough_reaches:
            continue
        rows.append({
            "branch_rva": branch_rva,
            "bytes": branch["bytes"],
            "mnemonic": branch["mnemonic"],
            "operands": branch["operands"],
            "taken_target_rva": int(target),
            "fallthrough_rva": following,
            "required_outcome": "TAKEN" if taken_reaches else "FALLTHROUGH",
        })
    return rows


def _distance(graph: dict[int, set[int]], start: int, target: int) -> int | None:
    queue = [(start, 0)]
    seen = set()
    for node, depth in queue:
        if node == target:
            return depth
        if node in seen or node not in graph:
            continue
        seen.add(node)
        queue.extend((value, depth + 1) for value in graph[node] if value not in seen)
    return None


def _outcome_sensitive_branches(instructions: list[dict[str, Any]], begin: int, end: int,
                                site_rva: int,
                                resolved_indirect: dict[int, list[int]] | None = None
                                ) -> list[dict[str, Any]]:
    """List conditional outcomes that can reach the site when the sibling outcome cannot."""
    graph = _successors(instructions, begin, end, resolved_indirect)
    from_entry = _reachable(graph, begin)
    rows = []
    for branch_rva in sorted(from_entry):
        branch = next(row for row in instructions if int(row["rva"]) == branch_rva)
        if "jump" not in set(branch.get("groups", [])) or branch["mnemonic"] == "jmp":
            continue
        target = branch.get("direct_target_rva")
        following = branch_rva + int(branch["size"])
        if target is None or int(target) not in graph or following not in graph:
            continue
        taken_reaches = site_rva in _reachable(graph, int(target))
        fallthrough_reaches = site_rva in _reachable(graph, following)
        if taken_reaches == fallthrough_reaches:
            continue
        reaching = int(target) if taken_reaches else following
        rows.append({
            "branch_rva": branch_rva, "bytes": branch["bytes"],
            "mnemonic": branch["mnemonic"], "operands": branch["operands"],
            "taken_target_rva": int(target), "fallthrough_rva": following,
            "required_outcome": "TAKEN" if taken_reaches else "FALLTHROUGH",
            "shortest_instruction_distance_to_callsite": _distance(graph, reaching, site_rva),
        })
    return sorted(rows, key=lambda row: (
        row["shortest_instruction_distance_to_callsite"]
        if row["shortest_instruction_distance_to_callsite"] is not None else 1 << 30,
        row["branch_rva"]))


def _callsite_path_status(instructions: list[dict[str, Any]], begin: int, end: int,
                          site_rva: int, resolved_indirect: dict[int, list[int]]
                          ) -> dict[str, Any]:
    graph = _successors(instructions, begin, end, resolved_indirect)
    reachable = _reachable(graph, begin)
    by_rva = {int(row["rva"]): row for row in instructions}
    unresolved = sorted(
        rva for rva in reachable
        if "jump" in set(by_rva[rva].get("groups", []))
        and by_rva[rva].get("direct_target_rva") is None
        and rva not in resolved_indirect)
    if site_rva not in reachable:
        return {"status": "CALLSITE_NOT_REACHED_BY_CURRENT_MECHANICAL_CFG",
                "unresolved_indirect_jump_rvas": unresolved,
                "mechanical_exit_count": 0, "callsite_dominates_all_exits": False}
    exits = sorted(node for node in reachable if not graph[node])
    dominators = _dominators(graph, begin)
    dominates_all = bool(exits) and all(site_rva in dominators[node] for node in exits)
    if unresolved:
        status = "CALLSITE_REACHABLE_BUT_CFG_HAS_UNRESOLVED_INDIRECT_CONTROL"
    elif dominates_all:
        status = "CALLSITE_MANDATORY_IN_COMPLETE_MECHANICAL_CFG"
    else:
        status = "CALLSITE_REACHABLE_BUT_NOT_MANDATORY_IN_COMPLETE_MECHANICAL_CFG"
    return {"status": status, "unresolved_indirect_jump_rvas": unresolved,
            "mechanical_exit_count": len(exits),
            "callsite_dominates_all_exits": dominates_all}


def build(relevance_path: Path, coverage_path: Path, game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    relevance = _load(relevance_path)
    coverage = _load(coverage_path)
    if relevance.get("schema") != "uc.ability-unobserved-static-relevance.v1":
        raise ValueError("unsupported unobserved-site relevance ledger")
    if coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported Ability coverage ledger")
    image = NativePE(game_path)
    coverage_by_type = {row["serialized_type"]: row for row in coverage["types"]}
    output_rows = []
    conditional_sites = [row for row in relevance["sites"]
                         if row["static_relevance_class"] ==
                         "RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH"]
    for site in conditional_sites:
        methods = [row for row in coverage_by_type[site["caller_type"]]["methods"]
                   if row["name"] == site["caller_method"]
                   and row.get("body_decode", {}).get("begin_rva") <= site["site_rva"]
                   < row.get("body_decode", {}).get("end_rva")]
        if len(methods) != 1:
            raise ValueError(f"callsite does not have one exact caller body: {site['site_rva']:#x}")
        method = methods[0]
        begin = int(method["body_decode"]["begin_rva"])
        end = int(method["body_decode"]["end_rva"])
        function = image.by_start.get(begin)
        if function is None or function.end != end:
            raise ValueError(f"caller PDATA boundary differs: {begin:#x}")
        decoded = image.decode(function)
        if not decoded["all_declared_bytes_decoded"]:
            raise ValueError(f"caller decode incomplete: {begin:#x}")
        cfg = image.cfg(function)
        resolved = {int(row["site_rva"]): [int(value) for value in row["target_rvas"]]
                    for row in cfg["resolved_indirect_branches"]}
        local_resolved = _resolve_local_jump_tables(
            image, decoded["instructions"], begin, end)
        resolved.update(local_resolved)
        try:
            gates = _gating_branches(decoded["instructions"], begin, end,
                                     int(site["site_rva"]), resolved)
            sensitive = _outcome_sensitive_branches(
                decoded["instructions"], begin, end, int(site["site_rva"]), resolved)
            path_status = _callsite_path_status(
                decoded["instructions"], begin, end, int(site["site_rva"]), resolved)
            cfg_analysis_status = path_status["status"]
        except ValueError as error:
            if "not reachable in mechanical CFG" not in str(error):
                raise
            gates = []
            sensitive = []
            cfg_analysis_status = "CALLSITE_NOT_REACHED_BY_CURRENT_MECHANICAL_CFG"
            path_status = {"status": cfg_analysis_status,
                           "unresolved_indirect_jump_rvas": [],
                           "mechanical_exit_count": 0,
                           "callsite_dominates_all_exits": False}
        positions = {int(row["rva"]): index for index, row in enumerate(decoded["instructions"])}
        for gate in sensitive:
            index = positions[gate["branch_rva"]]
            gate["preceding_instruction_window"] = [{
                "rva": int(row["rva"]), "bytes": row["bytes"],
                "mnemonic": row["mnemonic"], "operands": row["operands"],
                "regs_read": row.get("regs_read", []), "regs_write": row.get("regs_write", []),
            } for row in decoded["instructions"][max(0, index - 6):index]]
        output_rows.append({
            "point": site["point"], "site_rva": int(site["site_rva"]),
            "caller_type": site["caller_type"], "caller_method": site["caller_method"],
            "caller_begin_rva": begin, "caller_end_rva": end,
            "caller_decode_complete": True,
            "cfg_analysis_status": cfg_analysis_status,
            "path_coverage": path_status,
            "resolved_indirect_branch_count": len(resolved),
            "locally_resolved_jump_table_count": len(local_resolved),
            "unresolved_cfg_terminals": [row for row in cfg["terminals"]
                                         if row["terminal_semantics"] == "unresolved"],
            "gating_conditional_branch_count": len(gates),
            "gating_conditional_branches": gates,
            "outcome_sensitive_branch_count": len(sensitive),
            "outcome_sensitive_branches": sensitive,
            "semantic_predicate_assigned": False,
        })
    summary = {
        "runtime_conditional_sites": len(conditional_sites),
        "sites_with_exact_caller_body": len(output_rows),
        "sites_reachable_in_current_mechanical_cfg": sum(
            row["cfg_analysis_status"] != "CALLSITE_NOT_REACHED_BY_CURRENT_MECHANICAL_CFG"
            for row in output_rows),
        "sites_not_reached_by_current_mechanical_cfg": sum(
            row["cfg_analysis_status"] == "CALLSITE_NOT_REACHED_BY_CURRENT_MECHANICAL_CFG"
            for row in output_rows),
        "sites_mandatory_in_complete_mechanical_cfg": sum(
            row["cfg_analysis_status"] == "CALLSITE_MANDATORY_IN_COMPLETE_MECHANICAL_CFG"
            for row in output_rows),
        "sites_reachable_but_not_mandatory_in_complete_mechanical_cfg": sum(
            row["cfg_analysis_status"] ==
            "CALLSITE_REACHABLE_BUT_NOT_MANDATORY_IN_COMPLETE_MECHANICAL_CFG"
            for row in output_rows),
        "sites_with_remaining_unresolved_indirect_control": sum(
            row["cfg_analysis_status"] ==
            "CALLSITE_REACHABLE_BUT_CFG_HAS_UNRESOLVED_INDIRECT_CONTROL"
            for row in output_rows),
        "sites_with_mechanical_gating_branch": sum(
            row["gating_conditional_branch_count"] > 0 for row in output_rows),
        "total_mechanical_gating_branches": sum(
            row["gating_conditional_branch_count"] for row in output_rows),
        "sites_with_outcome_sensitive_branch": sum(
            row["outcome_sensitive_branch_count"] > 0 for row in output_rows),
        "total_outcome_sensitive_branches": sum(
            row["outcome_sensitive_branch_count"] for row in output_rows),
        "semantic_predicates_assigned": 0,
    }
    artifact = {
        "schema": "uc.ability-unobserved-branch-ledger.v1",
        "sources": {"static_relevance": _source(relevance_path),
                    "ability_coverage": _source(coverage_path),
                    "game_module": _source(game_path)},
        "summary": summary,
        "bounded_conclusions": [
            "gating branches are exact conditional instructions that dominate the callsite and only one outcome can reach it in the mechanical CFG",
            "preceding instruction windows preserve local register evidence but do not assign source-level predicate semantics",
            "absence of a mechanical gating branch does not prove unconditional execution when indirect control flow is unresolved",
            "runtime capture is not requested until a branch condition is joined to authoritative field or enum evidence",
        ],
        "runtime_needed_now": False,
        "sites": output_rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-unobserved-branch-ledger.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-unobserved-branch-ledger-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relevance", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.relevance.resolve(), args.coverage.resolve(),
                     args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_branch_ledger", error,
                      {"relevance": str(args.relevance), "coverage": str(args.coverage),
                       "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
