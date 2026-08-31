"""Build the final narrow controller closure source plan from game evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE


POINTS = (
    ("IntComparison.OnUpdate@0x1e471eb0", "game", 0x1E471EB0),
    ("BehaviorManager.LoadBehaviorComplete@0x1e45eef0", "game", 0x1E45EEF0),
    ("BehaviorManager.DestroyBehavior@0x1e467aa0", "game", 0x1E467AA0),
    ("SetTriggerParameter.OnUpdate@0x14a207b0", "game", 0x14A207B0),
    ("AnimatorFixedUpdate.invoker@0x4e30", "game", 0x4E30),
)


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _reg(rid: str, register: str, evidence: list[str], width: int = 8) -> dict[str, Any]:
    return {"id": rid, "base": register, "op": "register", "width": width,
            "phase": "enter", "evidence": evidence}


def _scalar(rid: str, base: str, offset: int, width: int,
            evidence: list[str]) -> dict[str, Any]:
    return {"id": rid, "base": base, "offset": offset, "op": "scalar", "width": width,
            "phase": "enter", "evidence": evidence}


def _block(rid: str, base: str, size: int, evidence: list[str]) -> dict[str, Any]:
    return {"id": rid, "base": base, "op": "block", "size": size,
            "phase": "enter", "evidence": evidence}


def _point(image: NativePE, point_id: str, module: str, rva: int,
           reads: list[dict[str, Any]], evidence: list[str], purpose: str,
           retention: dict[str, Any] | None = None) -> dict[str, Any]:
    owner = image.containing(rva)
    if owner is None or owner.begin != rva:
        raise ValueError(f"point is not an exact PDATA entry: {point_id}")
    row = {"id": point_id, "backend": "gum_probe", "module": module, "rva": rva,
           "expected_prefix": image.bytes_at(rva, 32).hex(), "reads": reads,
           "evidence": evidence, "capture_purpose": purpose,
           "interpretation": "instruction event at an evidence-qualified native entry"}
    if retention is not None:
        row["retention"] = retention
    return row


def _exact(return_rva: int, evidence: list[str]) -> dict[str, Any]:
    return {"mode": "first_per_entry_return_address", "max_keys": 1024,
            "exact_callers": [{"module": "game", "return_rva": return_rva,
                               "evidence": evidence}]}


def _invoker_wrapper_contract(image: NativePE) -> dict[str, Any]:
    """Verify the native register transfer that makes the hot parent redundant."""
    instructions = (
        (0xACDFF7, "4c89c6", "parent.r8 -> saved_rsi"),
        (0xACDFFA, "4889d3", "parent.rdx -> saved_rbx"),
        (0xACDFFD, "4889cf", "parent.rcx -> saved_rdi"),
        (0xACE045, "488b4f08", "child.rcx <- [saved_rdi+0x8]"),
        (0xACE049, "4889fa", "child.rdx <- saved_rdi"),
        (0xACE04C, "4989d8", "child.r8 <- adjusted_saved_rbx"),
        (0xACE04F, "4989f1", "child.r9 <- saved_rsi"),
        (0xACE052, "ff5710", "call [saved_rdi+0x10]"),
    )
    rows = []
    for rva, expected, meaning in instructions:
        observed = image.bytes_at(rva, len(expected) // 2).hex()
        if observed != expected:
            raise ValueError(f"invoker wrapper changed at {rva:#x}: {observed} != {expected}")
        rows.append({"rva": rva, "bytes": observed, "meaning": meaning})
    return {
        "wrapper_entry_rva": 0xACDFE0,
        "callsite_rva": 0xACE052,
        "continuation_rva": 0xACE055,
        "instructions": rows,
        "child_to_parent_mapping": {
            "child.rdx": "parent.rcx",
            "child.r9": "parent.r8",
            "child.r8": "parent.rdx adjusted by the source-observed instance rule",
            "child.rcx": "[parent.rcx+0x8]",
            "callee": "[parent.rcx+0x10]",
        },
        "not_recovered_from_child": ["parent.r9 exception-output pointer"],
    }


def run(module: Path, type_layout: Path, task_native: Path, task_ancestor: Path,
        task_receiver: Path, enum_decode: Path, api_usage: Path, closure_ledger: Path,
        reset_audit: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    image = NativePE(module)
    if image.bytes_at(0x1E46B6CA, 6).hex() != "ff9008010000":
        raise ValueError("RunTask OnUpdate virtual callsite changed")
    if image.bytes_at(0xACE052, 3).hex() != "ff5710":
        raise ValueError("selected API target invoker callsite changed")
    invoker_wrapper = _invoker_wrapper_contract(image)
    layout = type_layout.read_text(encoding="utf-8-sig")
    required_layout = (
        "public SharedInt integer2; // 0x50", "public SharedInt integer1; // 0x58",
        "public Operation operation; // 0x60", "public Behavior behavior; // 0x60",
        "private ExternalBehavior _externalBehavior; // 0x60",
        "private BehaviorSource mBehaviorSource; // 0x18", "public String behaviorName; // 0x10",
        "private OAFMFKKNHJA animatorComponent; // 0x58",
        "private Animator OJHBHGLAPCH; // 0x60",
    )
    missing = [row for row in required_layout if row not in layout]
    if missing:
        raise ValueError(f"runtime field layout changed: {missing}")

    paths = {
        "game-module": module, "runtime-field-layout": type_layout,
        "task-native-evidence": task_native, "task-ancestor-static-join": task_ancestor,
        "task-receiver-runtime-join": task_receiver,
        "int-comparison-enum-decode": enum_decode, "animator-api-usage": api_usage,
        "controller-closure-ledger": closure_ledger, "task-reset-dispatch-audit": reset_audit,
    }
    sources = {key: _source(path.resolve()) for key, path in paths.items()}
    task_refs = ["game-module", "runtime-field-layout", "task-native-evidence",
                 "task-ancestor-static-join", "int-comparison-enum-decode"]
    life_refs = ["game-module", "runtime-field-layout", "task-native-evidence",
                 "task-reset-dispatch-audit"]
    receiver_refs = ["game-module", "runtime-field-layout", "task-native-evidence",
                     "task-receiver-runtime-join"]
    api_refs = ["game-module", "animator-api-usage", "controller-closure-ledger"]

    int_reads = [
        _reg("task", "rcx", task_refs), _reg("behavior-tree", "rsi", task_refs),
        _reg("runtime-task-index", "rbx", task_refs, 4),
        _scalar("integer2", "rcx", 0x50, 8, task_refs),
        _scalar("integer2-constant", "integer2", 0x48, 4, task_refs),
        _scalar("integer1", "rcx", 0x58, 8, task_refs),
        _scalar("integer1-name", "integer1", 0x18, 8, task_refs),
        _block("integer1-name-object", "integer1-name", 96, task_refs),
        _scalar("operation", "rcx", 0x60, 4, task_refs),
        _scalar("tree-behavior", "rsi", 0x60, 8, task_refs),
        _scalar("external-behavior", "tree-behavior", 0x60, 8, task_refs),
        _scalar("external-source", "external-behavior", 0x18, 8, task_refs),
        _scalar("external-name", "external-source", 0x10, 8, task_refs),
        _block("external-name-object", "external-name", 128, task_refs),
    ]
    load_reads = [
        _reg("manager", "rcx", life_refs), _reg("behavior", "rdx", life_refs),
        _reg("behavior-tree", "r8", life_refs),
        _scalar("external-behavior", "rdx", 0x60, 8, life_refs),
        _scalar("external-source", "external-behavior", 0x18, 8, life_refs),
        _scalar("external-name", "external-source", 0x10, 8, life_refs),
        _block("external-name-object", "external-name", 128, life_refs),
    ]
    destroy_reads = [_reg("manager", "rcx", life_refs), _reg("behavior", "rdx", life_refs),
                     _reg("execution-status", "r8", life_refs, 4)]
    trigger_reads = [
        _reg("task", "rcx", receiver_refs), _reg("behavior-tree", "rsi", receiver_refs),
        _reg("runtime-task-index", "rbx", receiver_refs, 4),
        _scalar("animator-component", "rcx", 0x58, 8, receiver_refs),
        _scalar("nested-unity-animator", "animator-component", 0x60, 8, receiver_refs),
        _scalar("parameter-name", "rcx", 0x68, 8, receiver_refs),
        _block("parameter-name-object", "parameter-name", 96, receiver_refs),
        _scalar("owner-entity", "rcx", 0x70, 8, receiver_refs),
    ]
    invoker_reads = [_reg("bridge-code", "rcx", api_refs), _reg("method-object", "rdx", api_refs),
                     _reg("adjusted-argument", "r8", api_refs), _reg("argument-array", "r9", api_refs)]

    points = [
        _point(image, *POINTS[0], int_reads, task_refs, "five authoritative Remielle condition outcomes",
               _exact(0x1E46B6D0, task_refs)),
        _point(image, *POINTS[1], load_reads, life_refs, "Behavior to internal BehaviorTree load-complete boundary"),
        _point(image, *POINTS[2], destroy_reads, life_refs, "Behavior destruction boundary"),
        _point(image, *POINTS[3], trigger_reads, receiver_refs, "trigger component to nested Unity Animator"),
        _point(image, *POINTS[4], invoker_reads, api_refs, "selected GameAssembly invoker child",
               _exact(0xACE055, api_refs)),
    ]
    plan = {
        "schema": "uc.capture-plan.v1", "plan_id": "controller-exact-closure-v1",
        "plan_revision": 2,
        "modules": {"game": {"image": module.name, "sha256": file_hash(module)}},
        "sources": sources,
        "resources": {"slots_per_point": 4096, "max_record_bytes": 4096,
                      "capture_xmm": False},
        "points": points,
        "scope": {
            "purpose": "one reusable narrow run for condition outcomes, tree lifecycle, trigger receiver, and exact invoker continuation",
            "automatic_stop": False, "fixed_duration": False, "snapshot_limit": False,
            "reset_callback_repetition_required": False,
            "excluded_hot_parent": {
                "id": "SelectedEncryptedApiTarget@0xacdfe0",
                "reason": "the exact child plus source-verified caller continuation proves the required dispatch without full interception of the shared high-frequency parent",
            },
        },
    }
    validate(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_path = output / "capture-plan.controller-exact-closure.json"
    plan_path.write_bytes(canonical(plan))
    report = {"schema": "uc.controller-exact-closure-plan-report.v1",
              "plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
              "points": len(points), "exact_callers": 2,
              "full_hot_parent_points": 0, "capture_xmm": False,
              "excluded_hot_parent": "SelectedEncryptedApiTarget@0xacdfe0",
              "invoker_wrapper_contract": invoker_wrapper,
              "expected_runtime_rounds_after_qualification": 1,
              "runtime_required_now": True}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--task-native", type=Path, required=True)
    parser.add_argument("--task-ancestor", type=Path, required=True)
    parser.add_argument("--task-receiver", type=Path, required=True)
    parser.add_argument("--enum-decode", type=Path, required=True)
    parser.add_argument("--api-usage", type=Path, required=True)
    parser.add_argument("--closure-ledger", type=Path, required=True)
    parser.add_argument("--reset-audit", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(*(getattr(args, name).resolve() for name in (
        "module", "type_layout", "task_native", "task_ancestor", "task_receiver",
        "enum_decode", "api_usage", "closure_ledger", "reset_audit", "out")))
