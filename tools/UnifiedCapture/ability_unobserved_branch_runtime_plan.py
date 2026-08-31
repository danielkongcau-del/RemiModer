"""Prepare one read-only runtime unit for the 14 unobserved Ability branch inputs.

The plan observes the exact machine values consumed by one mechanically selected
conditional branch per unobserved site.  It deliberately does not assign
gameplay semantics to those values.  Multiple logical callsites sharing the
same predicate instruction are represented by one physical observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE
from uc.site_qualification import validate_site_qualification


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_PREDICATE = (ROOT / "extracted/analysis/ability-unobserved-predicate-join-"
                     "20260831-v1/ability-unobserved-predicate-join.json")
DEFAULT_BASE = (ROOT / "extracted/analysis/ability-unobserved-base-identity-join-"
                "20260831-v1/ability-unobserved-base-identity-join.json")
DEFAULT_BRANCH = (ROOT / "extracted/analysis/ability-unobserved-branch-ledger-"
                  "20260831-v6/ability-unobserved-branch-ledger.json")
DEFAULT_CLOSURE = (ROOT / "extracted/analysis/controller-closure-ledger-20260831-v42/"
                   "controller-closure-state.json")
DEFAULT_GAME = ROOT / "miHoYo Launcher/games/ZenlessZoneZero Game/GameAssembly.dll"

REGISTER_TEST = re.compile(r"([a-z0-9]+), \1$")
RIP_ZERO = re.compile(r"byte ptr \[rip ([+-]) (0x[0-9a-f]+)\], 0$")
MEMORY_ZERO = re.compile(r"byte ptr \[([a-z0-9]+) \+ (0x[0-9a-f]+)\], 0$")
STACK_LOAD = re.compile(r"([a-z0-9]+), qword ptr \[rsp \+ (0x[0-9a-f]+)\]$")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _reg(read_id: str, register: str, refs: list[str], width: int = 8) -> dict[str, Any]:
    return {"id": read_id, "base": register, "op": "register", "width": width,
            "phase": "enter", "evidence": refs}


def _scalar(read_id: str, base: str, offset: int, refs: list[str],
            width: int = 8) -> dict[str, Any]:
    return {"id": read_id, "base": base, "offset": offset, "op": "scalar",
            "width": width, "phase": "enter", "evidence": refs}


def _whole_instruction_window(image: NativePE, rva: int,
                              minimum: int = 32) -> tuple[bytes, list[dict[str, Any]]]:
    prefix = image.bytes_at(rva, minimum)
    instructions = []
    for instruction in image.cs.disasm(prefix, image.image_base + rva):
        instructions.append({
            "rva": instruction.address - image.image_base,
            "size": instruction.size,
            "mnemonic": instruction.mnemonic,
            "operands": instruction.op_str,
            "bytes": instruction.bytes.hex(),
        })
    if not instructions or instructions[0]["rva"] != rva:
        raise ValueError(f"{rva:#x}: predicate is not an instruction boundary")
    return prefix, instructions


def _near_relocation_span(instructions: list[dict[str, Any]]) -> int:
    span = 0
    for instruction in instructions:
        span += int(instruction["size"])
        if span >= 5:
            return span
    raise ValueError("no whole-instruction near redirect span")


def _rip_target(instruction: dict[str, Any]) -> int:
    match = RIP_ZERO.fullmatch(instruction["operands"])
    if instruction["mnemonic"] != "cmp" or not match:
        raise ValueError("not the bounded RIP-relative byte compare-zero shape")
    displacement = int(match.group(2), 0) * (1 if match.group(1) == "+" else -1)
    size = int(instruction.get("size", len(bytes.fromhex(instruction["bytes"]))))
    return int(instruction["rva"]) + size + displacement


def _dedupe_reads(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for row in rows:
        if row["id"] not in seen:
            seen.add(row["id"])
            result.append(row)
    return result


def _predicate_reads(predicate: dict[str, Any], base: dict[str, Any],
                     refs: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected = predicate["selected_branch"]
    instruction = selected["preceding_instruction_window"][-1]
    shape = predicate["predicate_machine_shape"]
    reads: list[dict[str, Any]] = []
    contract: dict[str, Any] = {
        "predicate_instruction_rva": int(instruction["rva"]),
        "predicate_instruction": {key: instruction[key] for key in
                                  ("rva", "bytes", "mnemonic", "operands")},
        "zero_branch_mnemonic": selected["mnemonic"],
        "required_branch_outcome_for_original_site": selected["required_outcome"],
        "semantic_gameplay_predicate_assigned": False,
    }

    if shape == "RIP_RELATIVE_MEMORY_COMPARE_ZERO":
        target = _rip_target(instruction)
        reads.append(_scalar(f"rip-byte@0x{target:x}", "module:game", target, refs, 1))
        contract["raw_tested_value"] = {"read_id": reads[-1]["id"],
                                        "identity": "MODULE_RELATIVE_BYTE"}
    elif shape == "REGISTER_ZERO_TEST":
        match = REGISTER_TEST.fullmatch(instruction["operands"])
        if instruction["mnemonic"] != "test" or not match:
            raise ValueError("register zero-test shape differs from exact instruction")
        register = match.group(1)
        width = 1 if register in ("al", "bl", "cl", "dl") else 8
        canonical_register = {"al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx"}.get(
            register, register)
        reads.append(_reg("tested-register", canonical_register, refs, width))
        contract["raw_tested_value"] = {"read_id": "tested-register",
                                        "machine_register": register}
        prior = selected["preceding_instruction_window"][-2]
        stack = STACK_LOAD.fullmatch(prior["operands"])
        if prior["mnemonic"] == "mov" and stack and stack.group(1) == register:
            offset = int(stack.group(2), 0)
            reads.append(_scalar(f"tested-stack-slot+0x{offset:x}", "rsp", offset,
                                 refs))
            contract["raw_tested_value"]["exact_stack_source_read_id"] = reads[-1]["id"]
    elif shape == "MEMORY_COMPARE":
        match = MEMORY_ZERO.fullmatch(instruction["operands"])
        if instruction["mnemonic"] != "cmp" or not match:
            raise ValueError("memory compare shape differs from exact instruction")
        register, offset = match.group(1), int(match.group(2), 0)
        reads.append(_reg(f"memory-base-{register}", register, refs))
        reads.append(_scalar("tested-memory-byte", f"memory-base-{register}", offset,
                             refs, 1))
        contract["raw_tested_value"] = {"read_id": "tested-memory-byte",
                                        "base_register": register, "offset": offset,
                                        "object_identity": "UNRESOLVED_SECONDARY_OBJECT"}
    else:
        raise ValueError(f"unsupported predicate shape: {shape}")

    aliases = base.get("stable_nonvolatile_this_aliases", {})
    for register, origin_rva in sorted(aliases.items()):
        read_id = f"this-alias-{register}"
        reads.append(_reg(read_id, register, refs))
        contract.setdefault("stable_this_aliases", {})[register] = int(origin_rva)

    # Preserve the exact statically proven field chain as redundant controls.
    # Unproven +0x20 accesses are still recorded, but remain explicitly unnamed.
    tested = base.get("selected_tested_value_provenance")
    if tested and tested.get("kind") == "EXACT_FIELD_LOAD":
        for access in base.get("accesses", []):
            provenance = access.get("base_provenance") or {}
            base_register = access["base_register"]
            if provenance.get("kind") == "THIS_ALIAS":
                read_base = f"this-alias-{base_register}"
            elif provenance.get("kind") == "EXACT_FIELD_LOAD":
                previous = next((row["id"] for row in reads
                                 if row["id"].startswith("exact-field-") and
                                 int(provenance.get("origin_rva", -1)) ==
                                 next((int(item["rva"]) for item in base.get("accesses", [])
                                       if item.get("exact_field") and
                                       f"exact-field-{item['exact_field']['class']}-"
                                       f"{item['exact_field']['field']}" == row["id"]), -2)), None)
                if previous is None:
                    continue
                read_base = previous
            else:
                continue
            field = access.get("exact_field")
            if not field:
                continue
            read_id = f"exact-field-{field['class']}-{field['field']}"
            reads.append(_scalar(read_id, read_base, int(access["offset"]), refs))
        contract["exact_tested_object_provenance"] = tested
    else:
        # If the selected load is directly based on the proven this alias,
        # preserve the unnamed offset without promoting it to a field identity.
        prior = selected["preceding_instruction_window"][-2]
        for register in aliases:
            direct = re.fullmatch(
                rf"[a-z0-9]+, qword ptr \[{register} \+ (0x[0-9a-f]+)\]",
                prior["operands"])
            if prior["mnemonic"] == "mov" and direct:
                offset = int(direct.group(1), 0)
                reads.append(_scalar(f"unnamed-this-offset+0x{offset:x}",
                                     f"this-alias-{register}", offset, refs))
                contract["unnamed_this_offset"] = offset
                break
    return _dedupe_reads(reads), contract


def build(predicate_path: Path, base_path: Path, branch_path: Path,
          closure_path: Path, game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    predicate = _load(predicate_path)
    base = _load(base_path)
    branch = _load(branch_path)
    closure = _load(closure_path)
    if predicate.get("schema") != "uc.ability-unobserved-predicate-join.v1":
        raise ValueError("unsupported predicate join")
    if base.get("schema") != "uc.ability-unobserved-base-identity-join.v1":
        raise ValueError("unsupported base-identity join")
    if branch.get("schema") != "uc.ability-unobserved-branch-ledger.v1":
        raise ValueError("unsupported branch ledger")
    if closure.get("schema") != "uc.controller-closure-state.v1" or closure.get(
            "runtime_required_now"):
        raise ValueError("closure ledger is not at the expected offline frontier")
    if (predicate.get("summary", {}).get("sites") != 14
            or base.get("summary", {}).get("sites") != 14
            or branch.get("summary", {}).get("runtime_conditional_sites") != 14):
        raise ValueError("14-site bounded frontier changed")
    predicate_by_point = {row["point"]: row for row in predicate["sites"]}
    base_by_point = {row["point"]: row for row in base["sites"]}
    branch_points = {row["point"] for row in branch["sites"]}
    if set(predicate_by_point) != set(base_by_point) or set(predicate_by_point) != branch_points:
        raise ValueError("predicate/base/branch point identities differ")

    image = NativePE(game_path)
    refs = ["predicate-join", "base-identity-join", "branch-ledger",
            "closure-ledger", "game-module"]
    represented: dict[int, list[str]] = defaultdict(list)
    contracts_by_rva: dict[int, list[dict[str, Any]]] = defaultdict(list)
    reads_by_rva: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for point in sorted(predicate_by_point):
        row = predicate_by_point[point]
        reads, contract = _predicate_reads(row, base_by_point[point], refs)
        rva = int(contract["predicate_instruction_rva"])
        represented[rva].append(point)
        contracts_by_rva[rva].append({"source_point": point,
                                      "selection_basis": row["selection_basis"],
                                      **contract})
        reads_by_rva[rva].extend(reads)

    windows = {}
    interior = set()
    for rva in represented:
        prefix, instructions = _whole_instruction_window(image, rva)
        near_span = _near_relocation_span(instructions)
        windows[rva] = (prefix, instructions, near_span)
        interior.update(range(rva + 1, rva + near_span))
    edges = image.direct_control_xrefs(interior)
    edges_by_target: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        edges_by_target[int(edge["target_rva"])].append(edge)

    points = []
    qualification_rows = []
    physical_contracts = []
    for rva in sorted(represented):
        prefix, instructions, near_span = windows[rva]
        interior_edges = [edge for target, rows in edges_by_target.items()
                          if rva < target < rva + near_span for edge in rows]
        if interior_edges:
            raise ValueError(f"{rva:#x}: direct edge enters near relocation interior")
        point_id = f"AbilityBranchInput.Predicate@0x{rva:x}"
        points.append({
            "id": point_id, "backend": "gum_probe", "module": "game", "rva": rva,
            "expected_prefix": prefix.hex(), "reads": _dedupe_reads(reads_by_rva[rva]),
            "evidence": refs,
            "capture_purpose": "raw input of one mechanically selected Ability path predicate",
            "interpretation": "pre-instruction machine values; no gameplay predicate assigned",
        })
        qualification_rows.append({
            "id": point_id + "/entry", "module": "game", "rva": rva,
            "verified_source_prefix": prefix.hex(), "semantic_safe_span": near_span,
            "safe_redirect_spans": [5], "direct_interior_edge_free": True,
            "static_evidence": {
                "instruction_boundary_span": near_span,
                "instructions": [row for row in instructions if row["rva"] < rva + near_span],
                "direct_edge_scan_scope": "all-file-backed-executable-sections",
                "direct_interior_edges": [],
            },
        })
        physical_contracts.append({
            "physical_predicate_rva": rva, "represented_source_points": represented[rva],
            "logical_contracts": contracts_by_rva[rva], "near_relocation_span": near_span,
        })

    sources = {
        "predicate-join": _source(predicate_path), "base-identity-join": _source(base_path),
        "branch-ledger": _source(branch_path), "closure-ledger": _source(closure_path),
        "game-module": _source(game_path), "plan-generator": _source(Path(__file__)),
    }
    plan = {
        "schema": "uc.capture-plan.v1", "plan_id": "ability-unobserved-branch-input-v1",
        "plan_revision": 1,
        "modules": {"game": {"image": game_path.name, "sha256": file_hash(game_path)}},
        "sources": sources,
        "resources": {"slots_per_point": 512, "max_record_bytes": 512,
                      "capture_xmm": False},
        "points": points,
        "scope": {
            "purpose": "observe raw inputs of the bounded 14-site Ability branch frontier",
            "automatic_stop": False, "fixed_duration": False, "snapshot_limit": False,
            "semantic_gameplay_predicates_assigned": False,
            "logical_source_sites": len(predicate_by_point),
            "physical_predicate_sites": len(represented),
        },
    }
    validate(plan, verify_sources=True)
    qualification = {
        "schema": "uc.probe-site-qualification.v1",
        "qualification_id": "ability-branch-input-" + hashlib.sha256(canonical(
            {"plan": plan["plan_id"], "revision": plan["plan_revision"],
             "sites": qualification_rows})).hexdigest()[:16],
        "modules": plan["modules"], "sites": qualification_rows,
    }
    validate_site_qualification(qualification)
    contract = {
        "schema": "uc.ability-unobserved-branch-runtime-contract.v1",
        "sources": sources,
        "summary": {
            "logical_source_sites": len(predicate_by_point),
            "physical_predicate_sites": len(represented),
            "coalesced_logical_sites": len(predicate_by_point) - len(represented),
            "strong_dominating_gate_sites": sum(
                row["selection_basis"] == "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE"
                for row in predicate_by_point.values()),
            "non_dominating_route_guard_sites": sum(
                row["selection_basis"] != "NEAREST_STRONG_DOMINATING_ONE_OUTCOME_GATE"
                for row in predicate_by_point.values()),
            "exact_tested_object_controls": base["summary"][
                "selected_test_values_with_exact_object_provenance"],
            "qualification_sites": len(qualification_rows),
            "near_only_sites": len(qualification_rows),
        },
        "physical_predicate_contracts": physical_contracts,
        "bounded_conclusions": [
            "records contain exact pre-instruction machine inputs, not inferred gameplay predicates",
            "the four non-dominating route guards remain execution-path observations and do not prove necessity",
            "the two exact tested-object chains are redundant controls for runtime read consistency",
            "absence remains unknown unless activation coverage and independent loss accounting are complete",
        ],
    }
    out.mkdir(parents=True)
    plan_path = out / "capture-plan.ability-unobserved-branch-input.json"
    qualification_path = out / "qualification.json"
    contract_path = out / "ability-unobserved-branch-runtime-contract.json"
    plan_path.write_bytes(canonical(plan))
    qualification_path.write_bytes(canonical(qualification))
    contract_path.write_bytes(canonical(contract))
    report = {
        "schema": "uc.ability-unobserved-branch-runtime-plan-report.v1",
        "plan": _source(plan_path), "qualification": _source(qualification_path),
        "static_contract": _source(contract_path), **contract["summary"],
        "activation_ready": False, "runtime_required_now": True,
        "next_step": "qualify all physical predicate sites in one target process before activation",
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predicate", type=Path, default=DEFAULT_PREDICATE)
    parser.add_argument("--base-identity", type=Path, default=DEFAULT_BASE)
    parser.add_argument("--branch-ledger", type=Path, default=DEFAULT_BRANCH)
    parser.add_argument("--closure-ledger", type=Path, default=DEFAULT_CLOSURE)
    parser.add_argument("--game", type=Path, default=DEFAULT_GAME)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.predicate.resolve(), args.base_identity.resolve(),
                     args.branch_ledger.resolve(), args.closure_ledger.resolve(),
                     args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_branch_runtime_plan", error, {
            "predicate": str(args.predicate), "base_identity": str(args.base_identity),
            "branch_ledger": str(args.branch_ledger),
            "closure_ledger": str(args.closure_ledger), "game": str(args.game),
        })
        raise


if __name__ == "__main__":
    run_main(main)
