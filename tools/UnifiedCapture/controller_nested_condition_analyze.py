"""Analyze the qualified nested ConditionalEvaluator runtime unit."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, inspect_session, read_manifest


POINT = "IntComparison.OnUpdate@0x1e471eb0/entry"
EXPECTED_CALLERS = {0x1F21899C, 0x1F218A55}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _value(reads: dict[str, dict[str, Any]], key: str) -> int:
    row = reads[key]
    if row.get("status") != 1 or not isinstance(row.get("value"), int):
        raise ValueError(f"required runtime read is unavailable: {key}")
    return row["value"]


def _decode_string(blob: bytes, read: dict[str, Any]) -> str:
    if read.get("status") != 1:
        raise ValueError("System.String block is unavailable")
    start, size = int(read["offset"]), int(read["length"])
    block = blob[start:start + size]
    if len(block) < 20:
        raise ValueError("System.String block is too short")
    count = int.from_bytes(block[16:20], "little", signed=True)
    if count < 0 or 20 + count * 2 > len(block):
        raise ValueError("System.String length is outside the captured block")
    return block[20:20 + count * 2].decode("utf-16-le", errors="strict")


def _verify_layout(path: Path) -> None:
    text = path.read_text(encoding="utf-8-sig", errors="strict")
    checks = (
        r"m_stringLength;\s*//\s*0x10",
        r"m_firstChar;\s*//\s*0x14",
        r"ConditionalEvaluator\s*:\s*Decorator\s*\{.*?conditionalTask;\s*//\s*0x60",
        r"IntComparison\s*:\s*Conditional\s*\{.*?integer2;\s*//\s*0x50.*?integer1;\s*//\s*0x58.*?operation;\s*//\s*0x60",
    )
    if any(re.search(pattern, text, re.S) is None for pattern in checks):
        raise ValueError("runtime field layout proof is incomplete")


def run(session_path: Path, acceptance_path: Path, plan_path: Path,
        task_ancestor_path: Path, enum_path: Path, type_layout_path: Path,
        output: Path) -> dict[str, Any]:
    session_path, acceptance_path, plan_path, task_ancestor_path, enum_path, \
        type_layout_path, output = [path.resolve() for path in (
            session_path, acceptance_path, plan_path, task_ancestor_path,
            enum_path, type_layout_path, output)]
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance, plan = _load(acceptance_path), _load(plan_path)
    ancestor, enum_decode = _load(task_ancestor_path), _load(enum_path)
    if not acceptance.get("accepted") or not acceptance.get("game_runtime_verified"):
        raise ValueError("entry acceptance is not accepted game-runtime evidence")
    if plan.get("plan_id") != "controller-nested-condition-closure-v1" or \
            [row.get("id") for row in plan.get("points", [])] != [POINT.removesuffix("/entry")]:
        raise ValueError("unexpected nested-condition plan identity")
    _verify_layout(type_layout_path)
    inspection = inspect_session(session_path)
    if not inspection.get("storage_complete") or inspection.get("cleanup") != "STOPPED_CLEAN" \
            or inspection.get("errors"):
        raise ValueError("session is not a clean sealed evidence store")
    manifest, errors = read_manifest(session_path / "session.manifest")
    if errors:
        raise ValueError(f"manifest errors: {errors}")
    context = event_dictionary_context(session_path / "session.manifest", manifest)
    generation = acceptance["generation"]
    activation = next(row for row in manifest if row.get("kind") == "plan_activation"
                      and row.get("generation") == generation)
    game_base = next(row["module_base"] for row in activation["bindings"]
                     if row["module"] == "game")
    enum_by_raw = {row["raw_value"]: row for row in enum_decode["mappings"]}

    expected = {}
    for task in ancestor.get("task_ancestor_rows", []):
        for condition in task.get("ancestor_conditions", []):
            signature = (condition["integer1_shared_name"],
                         condition["integer2_constant_raw"], condition["operation_raw"])
            expected[signature] = {
                "tree": condition["tree"], "serialized_task_index": condition["task_index"],
                "integer1_shared_name": signature[0], "integer2_constant_raw": signature[1],
                "operation_raw": signature[2],
                "operation_semantic": enum_by_raw[signature[2]]["native_predicate"],
            }
    if len(expected) != 5:
        raise ValueError("authoritative static condition set is not five nodes")

    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    exact_events = 0
    supplementary_events = 0
    for chunk in inspection["chunks"]:
        _, rows = decode_chunk_file(session_path / chunk["file"], dictionary_context=context)
        for _, _, event, blob in rows:
            if event.get("generation") != generation or event.get("point") != POINT:
                continue
            lane = event.get("retention_key", {}).get("lane")
            if lane != "exact_promoted":
                supplementary_events += 1
                continue
            exact_events += 1
            if event.get("read_failures") or event.get("truncated"):
                raise ValueError("exact-promoted nested condition evidence is incomplete")
            reads = {row["id"]: row for row in event["reads"]}
            task = _value(reads, "conditional-task")
            evaluator_task = _value(reads, "evaluator-conditional-task")
            task_owner = _value(reads, "task-owner-behavior")
            evaluator_owner = _value(reads, "evaluator-owner-behavior")
            if task != evaluator_task or task_owner != evaluator_owner:
                raise ValueError("ConditionalEvaluator runtime object relation is inconsistent")
            return_address = event["retention_key"]["value"]
            return_rva = return_address - game_base
            if return_rva not in EXPECTED_CALLERS:
                raise ValueError(f"unexpected exact caller: {return_rva:#x}")
            name = _decode_string(blob, reads["integer1-name-object"])
            constant, operation = _value(reads, "integer2-constant"), _value(reads, "operation")
            key = (return_rva, evaluator_owner, _value(reads, "task-id"), task,
                   _value(reads, "conditional-evaluator"), name, constant, operation)
            row = groups.setdefault(key, {"count": 0, "first_qpc": event["qpc"],
                "last_qpc": event["qpc"], "representative_event_id": event["event_id"]})
            row["count"] += 1
            row["first_qpc"] = min(row["first_qpc"], event["qpc"])
            row["last_qpc"] = max(row["last_qpc"], event["qpc"])

    observed_rows = []
    for key, aggregate in sorted(groups.items(), key=lambda item: tuple(str(x) for x in item[0])):
        signature = (key[5], key[6], key[7])
        observed_rows.append({"caller_return_rva": key[0], "owner_behavior": key[1],
            "task_id": key[2], "conditional_task": key[3], "conditional_evaluator": key[4],
            "integer1_shared_name": key[5], "integer2_constant_raw": key[6],
            "operation_raw": key[7],
            "operation_semantic": enum_by_raw.get(key[7], {}).get("native_predicate"),
            "matches_static_remielle_condition": signature in expected, **aggregate})
    observed_signatures = {(row["integer1_shared_name"], row["integer2_constant_raw"],
                            row["operation_raw"]) for row in observed_rows}
    expected_signatures = set(expected)
    matching = expected_signatures & observed_signatures
    status = ("OBSERVED_EXPECTED_CONDITION_SET" if expected_signatures <= observed_signatures else
              "OBSERVED_EXPECTED_CONDITION_SET_PARTIAL" if matching else
              "OBSERVED_DIFFERENT_CONDITION_SET")
    result = {"schema": "uc.controller-nested-condition-runtime-analysis.v1",
        "sources": {"session_manifest": _source(session_path / "session.manifest"),
            "entry_acceptance": _source(acceptance_path), "capture_plan": _source(plan_path),
            "task_ancestor_static_join": _source(task_ancestor_path),
            "int_comparison_enum_decode": _source(enum_path),
            "runtime_type_layout": _source(type_layout_path)},
        "session": {"session_id": inspection["chunks"][0]["session_id"],
            "generation": generation, "events": sum(row["event_count"] for row in inspection["chunks"]),
            "exact_events": exact_events, "supplementary_events": supplementary_events,
            "storage_complete": True, "cleanup": "STOPPED_CLEAN"},
        "conditions": {"status": status, "expected_static": list(expected.values()),
            "observed_runtime": observed_rows, "expected_signature_count": len(expected_signatures),
            "observed_signature_count": len(observed_signatures),
            "matching_signature_count": len(matching),
            "missing_static": [expected[key] for key in sorted(expected_signatures - observed_signatures)],
            "unexpected_runtime_signatures": [list(key) for key in sorted(
                observed_signatures - expected_signatures)]},
        "object_relations": {"owners": sorted({row["owner_behavior"] for row in observed_rows}),
            "matching_condition_owners": sorted({row["owner_behavior"] for row in observed_rows
                                                  if row["matches_static_remielle_condition"]}),
            "conditional_evaluator_to_task_consistent": True,
            "task_to_owner_consistent": True, "identity_level": "ObjectCandidate"},
        "controller_complete": False,
        "next": ("merge the observed five-condition set into the controller evidence graph"
                 if status == "OBSERVED_EXPECTED_CONDITION_SET" else
                 "statically narrow the remaining condition signatures before another runtime decision")}
    output.mkdir(parents=True)
    artifact = output / "controller-nested-condition-runtime-analysis.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-nested-condition-runtime-analysis-report.v1",
        "artifact": _source(artifact), "status": status, "events": exact_events,
        "matching_signature_count": len(matching), "expected_signature_count": len(expected_signatures),
        "controller_complete": False}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--task-ancestor", type=Path, required=True)
    parser.add_argument("--enum", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.session, args.acceptance, args.plan, args.task_ancestor, args.enum,
            args.type_layout, args.out)
    except Exception as error:
        write_failure(args.out, "controller_nested_condition_analyze", error,
                      sources=[path for path in (args.session, args.acceptance, args.plan,
                          args.task_ancestor, args.enum, args.type_layout) if path.exists()])
        raise
