"""Mechanically close static semantics behind unobserved controller points.

This derivation deliberately separates two questions:

* what the selected native implementation does (static, source-bound), and
* whether that implementation executed in a covered runtime window.

It does not promote a NOT_OBSERVED point to an observed one.  It only joins
the field-read plan, harvested method identities, and decoded GameAssembly
instructions into a reproducible static statement.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


RESET_RVAS = (0x1F76E830, 0x1F836580, 0x14A20AC0, 0x14A1F830)
JOB_EXECUTE_RVA = 0x007C01B0
JOB_WRAPPER_RVA = 0x07585E30
JOB_SHARED_BODY_RVA = 0x12DF4580
JOB_CONSUMER_RVA = 0x15FE6D20


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _one(rows: list[dict[str, Any]], description: str) -> dict[str, Any]:
    if len(rows) != 1:
        raise ValueError(f"expected exactly one {description}, got {len(rows)}")
    return rows[0]


def _functions(native: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for row in native.get("functions", []):
        rva = int(row["rva"])
        if rva in result:
            raise ValueError(f"duplicate native function RVA: {rva:#x}")
        result[rva] = row
    return result


def _merge_frontier_functions(result: dict[int, dict[str, Any]], frontier: dict[str, Any]) -> None:
    """Add later source-bound manifest functions without weakening old evidence."""
    for row in frontier.get("functions", []):
        rva = int(row["entry_rva"])
        instructions = []
        for instruction in row.get("capstone_instructions", []):
            item = dict(instruction)
            if "direct_target_rva" in item:
                item["directTargetRva"] = item.pop("direct_target_rva")
            instructions.append(item)
        normalized = {
            "rva": rva,
            "extent": "pdata" if row.get("runtime_functions") else "unknown",
            "allDeclaredBytesDecoded": bool(row.get("capstone_cfg", {}).get("decode_complete")),
            "names": [row.get("function_id", "")],
            "instructions": instructions,
        }
        if rva in result:
            existing = result[rva]
            old = [(ins.get("rva"), ins.get("bytes")) for ins in existing.get("instructions", [])]
            new = [(ins.get("rva"), ins.get("bytes")) for ins in normalized["instructions"]]
            if old and new and old != new:
                raise ValueError(f"native/frontier instruction disagreement at {rva:#x}")
            continue
        result[rva] = normalized


def _identities(native: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in native.get("methodInventory", []):
        result[int(row["rva"])].append({key: row.get(key) for key in (
            "typeIndex", "depth", "name", "method", "rva", "slot", "source", "sourceLine")})
    return result


def _runtime_points(acceptance: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for row in acceptance.get("points", []):
        match = re.search(r"@0x([0-9a-fA-F]+)$", row["function_id"])
        if match:
            result[int(match.group(1), 16)] = row
    return result


def _plan_points(plan: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for row in plan.get("points", []):
        rva = int(row["rva"])
        if rva in result:
            raise ValueError(f"duplicate plan point RVA: {rva:#x}")
        result[rva] = row
    return result


def _field_map(point: dict[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for read in point.get("reads", []):
        if read.get("base") != "rcx" or "runtime-field-layout" not in read.get("evidence", []):
            continue
        offset = int(read["offset"])
        if offset in result:
            raise ValueError(f"duplicate field offset at {point['id']}: {offset:#x}")
        result[offset] = read
    if not result:
        raise ValueError(f"no source-verified field reads at {point['id']}")
    return result


def _target_identity(target: int, identities: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    rows = identities.get(target, [])
    named = [row for row in rows if row.get("name")]
    row = _one(named, f"harvested identity for call target {target:#x}")
    return {"rva": target, "rva_hex": f"0x{target:x}", "name": row["name"],
            "type_id": row["typeIndex"], "source": row["source"],
            "source_line": row["sourceLine"]}


def _reset_semantics(point: dict[str, Any], runtime: dict[str, Any], function: dict[str, Any],
                     identities: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    if not function.get("allDeclaredBytesDecoded") or function.get("extent") != "pdata":
        raise ValueError(f"reset function is not a complete PDATA decode: {point['id']}")
    if not any(name.startswith(point["id"].split("@", 1)[0] + ".") for name in function.get("names", [])):
        raise ValueError(f"native identity mismatch for {point['id']}")

    fields = _field_map(point)
    instructions = function["instructions"]
    try:
        normal_return = next(index for index, ins in enumerate(instructions)
                             if ins["mnemonic"] == "ret")
    except StopIteration as error:
        raise ValueError(f"reset function has no normal return: {point['id']}") from error
    core = instructions[:normal_return]
    operations: list[dict[str, Any]] = []
    written: set[int] = set()
    pattern = re.compile(r"qword ptr \[rsi \+ 0x([0-9a-fA-F]+)\], (0|rax)$")
    for index, ins in enumerate(core):
        if ins["mnemonic"] != "mov":
            continue
        match = pattern.fullmatch(ins["operands"])
        if not match:
            continue
        offset = int(match.group(1), 16)
        if offset not in fields:
            raise ValueError(f"native reset writes unknown harvested offset {offset:#x} at {point['id']}")
        if offset in written:
            raise ValueError(f"native reset writes harvested offset twice {offset:#x} at {point['id']}")
        written.add(offset)
        operation: dict[str, Any] = {
            "instruction_rva": int(ins["rva"]), "field": fields[offset]["id"],
            "offset": offset, "offset_hex": f"0x{offset:x}",
        }
        if match.group(2) == "0":
            operation["operation"] = "write-null-pointer"
        else:
            if index == 0 or core[index - 1]["mnemonic"] != "call" or "directTargetRva" not in core[index - 1]:
                raise ValueError(f"rax field store is not immediately sourced by a direct call at {point['id']}")
            target = int(core[index - 1]["directTargetRva"])
            identity = _target_identity(target, identities)
            if not identity["name"].endswith("op_Implicit.1"):
                raise ValueError(f"reset assignment target is not a harvested implicit conversion: {identity['name']}")
            operation.update({"operation": "write-call-result", "producer": identity,
                              "input_zeroed": index >= 2 and core[index - 2]["mnemonic"] == "xor"
                              and core[index - 2]["operands"] == "ecx, ecx"})
        operations.append(operation)
    if not operations:
        raise ValueError(f"no reset field operations derived at {point['id']}")
    untouched = [{"field": read["id"], "offset": offset, "offset_hex": f"0x{offset:x}"}
                 for offset, read in sorted(fields.items()) if offset not in written]
    return {
        "point": point["id"] + "/entry", "function_rva": int(point["rva"]),
        "function_rva_hex": f"0x{int(point['rva']):x}",
        "type_authority": point["field_read_contract"]["authority"],
        "runtime_status": runtime["status"], "runtime_evidence_scope": runtime.get("evidence_scope"),
        "static_implementation_status": "SOURCE_VERIFIED",
        "normal_path_field_operations": operations,
        "harvested_fields_not_written_on_normal_path": untouched,
        "claim_boundary": "static normal-path implementation only; runtime callback execution is not implied",
    }


def _find_direct(function: dict[str, Any], mnemonic: str, target: int) -> list[dict[str, Any]]:
    return [ins for ins in function.get("instructions", [])
            if ins.get("mnemonic") == mnemonic and ins.get("directTargetRva") is not None
            and int(ins["directTargetRva"]) == target]


def _job_chain(plan_point: dict[str, Any], runtime: dict[str, Any], functions: dict[int, dict[str, Any]],
               identities: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    wrapper = functions[JOB_WRAPPER_RVA]
    execute = functions[JOB_EXECUTE_RVA]
    shared = functions[JOB_SHARED_BODY_RVA]
    consumer = functions[JOB_CONSUMER_RVA]
    if not wrapper.get("allDeclaredBytesDecoded") or wrapper.get("extent") != "pdata":
        raise ValueError("closed generic job wrapper is not a complete PDATA decode")
    if not shared.get("allDeclaredBytesDecoded") or not consumer.get("allDeclaredBytesDecoded"):
        raise ValueError("shared job body or consumer is not a complete decode")
    identity = _target_identity(JOB_EXECUTE_RVA, identities)
    if identity["name"] != "IKNHGFBHLLK.Execute.0":
        raise ValueError(f"unexpected concrete job identity: {identity['name']}")
    if [(ins["mnemonic"], ins["operands"], ins.get("directTargetRva")) for ins in execute["instructions"]] != [
            ("add", "rcx, 0x10", None), ("jmp", "0x192df4580", JOB_SHARED_BODY_RVA)]:
        raise ValueError("concrete job Execute thunk instruction contract drifted")
    wrapper_calls = _find_direct(wrapper, "call", JOB_SHARED_BODY_RVA)
    shared_jumps = _find_direct(shared, "jmp", JOB_CONSUMER_RVA)
    if len(wrapper_calls) != 1 or len(shared_jumps) != 1:
        raise ValueError("job wrapper/shared-body dispatch chain is not unique")
    return {
        "closed_type": plan_point["field_read_contract"]["authority"]["closed_type"],
        "runtime_observation_point": plan_point["id"] + "/entry",
        "runtime_status": runtime["status"], "runtime_evidence_scope": runtime.get("evidence_scope"),
        "concrete_method_identity": identity,
        "concrete_execute_thunk": {"rva": JOB_EXECUTE_RVA, "adjusts_rcx_by": 0x10,
                                   "jumps_to_rva": JOB_SHARED_BODY_RVA},
        "generated_wrapper": {"rva": JOB_WRAPPER_RVA,
                              "calls_shared_body_at_rva": int(wrapper_calls[0]["rva"]),
                              "shared_body_rva": JOB_SHARED_BODY_RVA},
        "shared_body": {"rva": JOB_SHARED_BODY_RVA,
                        "jumps_to_consumer_at_rva": int(shared_jumps[0]["rva"]),
                        "consumer_rva": JOB_CONSUMER_RVA,
                        "consumer_identity": consumer.get("names", [])},
        "static_chain_status": "SOURCE_VERIFIED",
        "claim_boundary": "static dispatch identity and path only; the runtime branch was not observed in this window",
    }


def run(plan_path: Path, acceptance_path: Path, native_path: Path, output: Path,
        frontier_path: Path | None = None) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    plan, acceptance, native = _load(plan_path), _load(acceptance_path), _load(native_path)
    functions = _functions(native)
    frontier = _load(frontier_path) if frontier_path else None
    if frontier:
        _merge_frontier_functions(functions, frontier)
    points, runtime, identities = (_plan_points(plan), _runtime_points(acceptance), _identities(native))
    reset_rows = []
    for rva in RESET_RVAS:
        if rva not in points or rva not in runtime or rva not in functions:
            raise ValueError(f"missing reset evidence at RVA {rva:#x}")
        reset_rows.append(_reset_semantics(points[rva], runtime[rva], functions[rva], identities))
    if JOB_WRAPPER_RVA not in points or JOB_WRAPPER_RVA not in runtime:
        raise ValueError("missing generated job-wrapper plan/runtime evidence")
    job = _job_chain(points[JOB_WRAPPER_RVA], runtime[JOB_WRAPPER_RVA], functions, identities)
    result = {
        "schema": "uc.controller-static-gap-analysis.v1",
        "sources": {"capture-plan": _source(plan_path), "runtime-acceptance": _source(acceptance_path),
                    "native-evidence": _source(native_path),
                    **({"source-bound-frontier": _source(frontier_path)} if frontier_path else {})},
        "reset_implementations": reset_rows,
        "parallel_job_dispatch": job,
        "checks": {"reset_implementation_count": len(reset_rows),
                   "all_reset_implementations_source_verified": all(
                       row["static_implementation_status"] == "SOURCE_VERIFIED" for row in reset_rows),
                   "all_reset_entries_not_observed": all(
                       row["runtime_status"] == "NOT_OBSERVED_IN_COVERED_WINDOW" for row in reset_rows),
                   "parallel_job_static_chain_source_verified": job["static_chain_status"] == "SOURCE_VERIFIED",
                   "parallel_job_wrapper_not_observed": job["runtime_status"] == "NOT_OBSERVED_IN_COVERED_WINDOW"},
        "conclusions": [
            "The normal-path field effects of the four selected OnReset implementations are statically closed.",
            "This run does not prove that any selected OnReset callback executed for Remielle.",
            "The concrete job method, generated wrapper, shared body, and ODK consumer are statically joined.",
            "This run does not prove that the generated parallel-job wrapper branch executed for Remielle.",
        ],
        "next_runtime_scope": [
            "Observe OnReset only if callback execution/lifetime proof is required; do not repeat gameplay to rediscover its implementation.",
            "Observe the generated wrapper/shared body only if Remielle branch selection is required; do not repeat gameplay to rediscover the static dispatch chain.",
        ],
        "not_proven": ["ObjectInstance", "Remielle EntityIdentity", "per-move attribution",
                       "cross-thread causality", "complete controller"],
    }
    output.mkdir(parents=True)
    artifact = output / "controller-static-gap-analysis.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-static-gap-analysis-report.v1",
              "artifact": _source(artifact), **result["checks"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--native-evidence", type=Path, required=True)
    parser.add_argument("--frontier-manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.plan.resolve(), args.acceptance.resolve(),
             args.native_evidence.resolve(), args.out.resolve(),
             args.frontier_manifest.resolve() if args.frontier_manifest else None)
