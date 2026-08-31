"""Prepare the one-site plan for nested BehaviorDesigner conditions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE
from uc.store import read_manifest


# A physical observation point keeps one stable identity across plans.  The
# nested-condition scope is expressed by this plan's purpose and exact-caller
# retention, not by minting a second identity for the same instruction RVA.
POINT = "IntComparison.OnUpdate@0x1e471eb0"
ENTRY_RVA = 0x1E471EB0


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _verify_layout(path: Path) -> None:
    text = path.read_text(encoding="utf-8-sig", errors="strict")
    required = (
        r"ConditionalEvaluator\s*:\s*Decorator\s*\{.*?conditionalTask;\s*//\s*0x60",
        r"ParentTask\s*:\s*Task\s*\{.*?children;\s*//\s*0x50",
        r"Task\s*:\s*Object\s*\{.*?Behavior\s+owner;\s*//\s*0x28.*?int\s+id;\s*//\s*0x40",
        r"IntComparison\s*:\s*Conditional\s*\{.*?integer2;\s*//\s*0x50.*?integer1;\s*//\s*0x58.*?operation;\s*//\s*0x60",
        r"Behavior\s*:\s*MonoBehaviour\s*\{.*?ExternalBehavior\s+_externalBehavior;\s*//\s*0x60",
        r"ExternalBehavior\s*:\s*ScriptableObject\s*\{.*?BehaviorSource\s+mBehaviorSource;\s*//\s*0x18",
        r"BehaviorSource\s*:\s*Object\s*\{.*?String\s+behaviorName;\s*//\s*0x10",
        r"SharedVariable\s*:\s*Object\s*\{.*?String\s+mName;\s*//\s*0x18",
    )
    if any(re.search(pattern, text, re.S) is None for pattern in required):
        raise ValueError("nested condition field layout proof is incomplete")


def _caller_contract(image: NativePE, return_rva: int) -> dict[str, Any]:
    call_rva = None
    row = image.containing(return_rva - 1)
    if row is None:
        raise ValueError(f"caller return RVA is outside .pdata: {return_rva:#x}")
    decoded = image.decode(row)
    if not decoded["all_declared_bytes_decoded"]:
        raise ValueError(f"caller function is not completely decoded: {row.begin:#x}")
    instructions = decoded["instructions"]
    for index, instruction in enumerate(instructions):
        if instruction["rva"] + instruction["size"] == return_rva and "call" in instruction["groups"]:
            call_rva = instruction["rva"]
            call_index = index
            break
    if call_rva is None:
        raise ValueError(f"return RVA has no unique predecessor call: {return_rva:#x}")
    window = instructions[max(0, call_index - 12):call_index + 1]
    predicates = {
        "callee_loaded_from_evaluator": any(row["mnemonic"] == "mov" and row["operands"] ==
            "rcx, qword ptr [rsi + 0x60]" for row in window),
        "virtual_slot_call": instructions[call_index]["mnemonic"] == "call" and
            instructions[call_index]["operands"] == "qword ptr [rax + 0x108]",
        "second_argument_zero": any(row["mnemonic"] == "xor" and row["operands"] == "edx, edx"
                                    for row in window),
        "evaluator_preserved_in_rsi": any(row["mnemonic"] == "mov" and row["operands"] == "rsi, rcx"
                                          for row in instructions[:8]),
    }
    if not all(predicates.values()):
        raise ValueError(f"ConditionalEvaluator caller ABI contract failed: {return_rva:#x}")
    return {"function_begin_rva": row.begin, "function_end_rva": row.end,
            "callsite_rva": call_rva, "return_rva": return_rva,
            "instructions": window, "checks": predicates}


def _reg(identifier: str, base: str, evidence: list[str], width: int = 8) -> dict[str, Any]:
    return {"id": identifier, "op": "register", "phase": "enter", "base": base,
            "width": width, "evidence": evidence}


def _scalar(identifier: str, base: str, offset: int, width: int,
            evidence: list[str]) -> dict[str, Any]:
    return {"id": identifier, "op": "scalar", "phase": "enter", "base": base,
            "offset": offset, "width": width, "evidence": evidence}


def _block(identifier: str, base: str, size: int, evidence: list[str]) -> dict[str, Any]:
    return {"id": identifier, "op": "block", "phase": "enter", "base": base,
            "size": size, "evidence": evidence}


def run(session_path: Path, acceptance_path: Path, analysis_path: Path,
        module_path: Path, disassembly_path: Path, type_layout_path: Path,
        output: Path) -> dict[str, Any]:
    session_path, acceptance_path, analysis_path, module_path, disassembly_path, \
        type_layout_path, output = [
        path.resolve() for path in (session_path, acceptance_path, analysis_path, module_path,
                                    disassembly_path, type_layout_path, output)]
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance, analysis = _load(acceptance_path), _load(analysis_path)
    if not acceptance.get("accepted") or not acceptance.get("game_runtime_verified"):
        raise ValueError("source runtime acceptance is not accepted game evidence")
    if analysis.get("schema") != "uc.controller-exact-closure-runtime-analysis.v1" \
            or analysis.get("conditions", {}).get("target_status") != "OBSERVED_DIFFERENT_CONDITION_SET":
        raise ValueError("source analysis does not establish the direct-caller mismatch")
    _verify_layout(type_layout_path)
    manifest, errors = read_manifest(session_path / "session.manifest")
    if errors:
        raise ValueError(f"manifest errors: {errors}")
    activation = next(row for row in manifest if row.get("kind") == "plan_activation"
                      and row.get("generation") == acceptance["generation"])
    game_bindings = [row for row in activation["bindings"] if row["module"] == "game"]
    game_base = game_bindings[0]["module_base"]
    if any(row["module_base"] != game_base for row in game_bindings):
        raise ValueError("GameAssembly base changed inside activation")
    point = next(row for row in acceptance["points"]
                 if row["point"] == "IntComparison.OnUpdate@0x1e471eb0/entry")
    summary = point["retention_generation"]
    aggregate = [row for row in summary["keys"] if row.get("lane") == "aggregate_first_sample"]
    return_rvas = sorted({int(row["entry_return_address"]) - game_base for row in aggregate})
    if return_rvas != [0x1F21899C, 0x1F218A55]:
        raise ValueError(f"unexpected nested-condition caller set: {[hex(x) for x in return_rvas]}")
    image = NativePE(module_path)
    contracts = [_caller_contract(image, rva) for rva in return_rvas]
    evidence = ["game-module", "runtime-type-layout", "accepted-exact-closure-runtime",
                "exact-closure-analysis", "conditional-evaluator-callsite-contract"]
    reads = [
        _reg("conditional-task", "rcx", evidence),
        _reg("conditional-evaluator", "rsi", evidence),
        _scalar("evaluator-conditional-task", "rsi", 0x60, 8, evidence),
        _scalar("evaluator-owner-behavior", "rsi", 0x28, 8, evidence),
        _scalar("task-owner-behavior", "rcx", 0x28, 8, evidence),
        _scalar("task-id", "rcx", 0x40, 4, evidence),
        _scalar("integer2", "rcx", 0x50, 8, evidence),
        _scalar("integer2-constant", "integer2", 0x48, 4, evidence),
        _scalar("integer1", "rcx", 0x58, 8, evidence),
        _scalar("integer1-name", "integer1", 0x18, 8, evidence),
        _block("integer1-name-object", "integer1-name", 96, evidence),
        _scalar("operation", "rcx", 0x60, 4, evidence),
    ]
    expected_prefix = image.bytes_at(ENTRY_RVA, 32).hex()
    sources = {"game-module": _source(module_path),
        # This separately named authority is deliberate: every evidence label
        # must resolve in the v1 source table, while the contract itself was
        # mechanically decoded from the pinned game image above.
        "conditional-evaluator-callsite-contract": _source(disassembly_path),
        "runtime-type-layout": _source(type_layout_path),
        "accepted-exact-closure-runtime": _source(acceptance_path),
        "exact-closure-analysis": _source(analysis_path)}
    plan = {"schema": "uc.capture-plan.v1", "plan_id": "controller-nested-condition-closure-v1",
        "plan_revision": 1,
        "modules": {"game": {"image": "GameAssembly.dll", "sha256": file_hash(module_path)}},
        "sources": sources,
        "resources": {"slots_per_point": 1024, "max_record_bytes": 2048, "capture_xmm": False},
        "scope": {"purpose": "capture nested ConditionalEvaluator condition tasks with their owner Behavior",
                  "automatic_stop": False, "fixed_duration": False, "snapshot_limit": False,
                  "estimated_source_runtime_callbacks": sum(int(row["count"]) for row in aggregate),
                  "source_activation_qpc": acceptance["action_window_qpc"]},
        "points": [{"id": POINT, "module": "game", "rva": ENTRY_RVA,
            "backend": "gum_probe", "expected_prefix": expected_prefix,
            "interpretation": "instruction event at the source-qualified IntComparison entry",
            "capture_purpose": "nested ConditionalEvaluator task identity, condition operands, and owner Behavior",
            "evidence": evidence, "reads": reads,
            "retention": {"mode": "first_per_entry_return_address", "max_keys": 1024,
                "exact_callers": [{"module": "game", "return_rva": rva,
                    "evidence": evidence} for rva in return_rvas]}}]}
    output.mkdir(parents=True)
    plan_path = output / "capture-plan.controller-nested-condition.json"
    plan_path.write_bytes(canonical(plan))
    report = {"schema": "uc.controller-nested-condition-plan-report.v1",
        "plan": _source(plan_path), "physical_points": 1, "exact_callers": return_rvas,
        "source_aggregate_counts": {hex(int(row["entry_return_address"]) - game_base): row["count"]
                                    for row in aggregate},
        "caller_contracts": contracts, "capture_xmm": False,
        "runtime_required_now": True, "expected_additional_runtime_rounds": 1}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.session, args.acceptance, args.analysis, args.module, args.disassembly,
            args.type_layout, args.out)
    except Exception as error:
        write_failure(args.out, "controller_nested_condition_plan", error)
        raise
