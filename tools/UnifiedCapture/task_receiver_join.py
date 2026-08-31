"""Join Remielle runtime task candidates to the native receiver fields they consume."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


DIRECT_ANIMATOR_TYPES = {34455, 34459}
COMPONENT_ANIMATOR_TYPES = {41564}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _nonzero(values: Any) -> list[int]:
    if not isinstance(values, list):
        return []
    return sorted({int(value) for value in values if type(value) is int and value != 0})


def _verify_native_consumption(authority: dict[str, Any]) -> dict[int, dict[str, Any]]:
    methods = {int(row["typeIndex"]): row for row in authority.get("nativeMethods", [])
               if row.get("method") == "OnUpdate" and type(row.get("typeIndex")) is int}
    instructions = authority.get("nativeWitness", {}).get("checkedInstructions", [])
    expected = {
        34455: "qword ptr [rsi + 0x70]",
        34459: "qword ptr [rsi + 0x70]",
        41564: "qword ptr [rsi + 0x58]",
    }
    verified = {}
    for type_index, operand in expected.items():
        method = methods.get(type_index)
        if method is None:
            raise ValueError(f"native OnUpdate authority absent for type {type_index}")
        hits = [row for row in instructions
                if row.get("mnemonic") == "mov" and operand in str(row.get("operands", ""))
                and int(row.get("rva", -1)) >= int(method["rva"])]
        if not hits:
            raise ValueError(f"receiver-field consumption instruction absent for type {type_index}")
        verified[type_index] = {
            "method_rva": int(method["rva"]),
            "receiver_load": hits[0],
            "receiver_semantics": ("UnityEngine.Animator field at task+0x70"
                                   if type_index in DIRECT_ANIMATOR_TYPES else
                                   "game Animator component field at task+0x58"),
        }
    return verified


def analyze(task_join: dict[str, Any], lifecycle: dict[str, Any],
            authority: dict[str, Any]) -> dict[str, Any]:
    if task_join.get("schema") != "uc.task-context-static-join.v1":
        raise ValueError("unsupported task context join")
    if lifecycle.get("schema") != "uc.controller-field-lifecycle-analysis.v1":
        raise ValueError("unsupported field lifecycle analysis")
    if authority.get("schema") != "zzz.existing-task-register-consumption.v1":
        raise ValueError("unsupported native task consumption authority")
    native = _verify_native_consumption(authority)
    trees = [row for row in task_join.get("behavior_trees", [])
             if row.get("identity_status") == "UNIQUE_STATIC_TASK_SIGNATURE_MATCH"
             and len(row.get("candidate_static_trees", [])) == 1
             and row["candidate_static_trees"][0].get("root_tree") ==
             "Behavior_Avatar_RemielleOrigin_Decision"]
    if len(trees) != 1:
        raise ValueError("one unique Remielle Origin runtime tree is required")
    tree = trees[0]
    address = int(tree["behavior_tree_address"])
    signature = {(int(row["runtime_task_index"]), int(row["native_type_index"]))
                 for row in tree.get("observed_task_signature", [])}
    contexts = [row for row in task_join.get("contexts", [])
                if int(row.get("behavior_tree_address", -1)) == address
                and (int(row["runtime_task_index"]), int(row["native_type_index"])) in signature]
    by_address = {int(row["observed_address"]): row for row in lifecycle.get("candidates", [])
                  if row.get("candidate_kind") == "parameter-task"}
    rows = []
    for context in sorted(contexts, key=lambda row: (row["runtime_task_index"],
                                                      row["native_type_index"])):
        task_addresses = [int(value) for value in context.get("task_addresses", [])]
        if len(task_addresses) != 1:
            raise ValueError("each retained Remielle task context must identify one task address")
        candidate = by_address.get(task_addresses[0])
        if candidate is None:
            raise ValueError("Remielle task address lacks field-lifecycle evidence")
        type_index = int(context["native_type_index"])
        fields = candidate.get("field_values", {})
        if type_index in DIRECT_ANIMATOR_TYPES:
            receiver_kind = "UnityEngine.Animator"
            receivers = _nonzero(fields.get("animator-object"))
        elif type_index in COMPONENT_ANIMATOR_TYPES:
            receiver_kind = "game Animator component"
            receivers = _nonzero(fields.get("animator-component"))
        else:
            raise ValueError(f"unsupported receiver contract for type {type_index}")
        if len(receivers) != 1:
            raise ValueError("task receiver field is absent or ambiguous")
        rows.append({
            "runtime_task_index": int(context["runtime_task_index"]),
            "native_type_index": type_index,
            "task_address": task_addresses[0],
            "receiver_kind": receiver_kind,
            "receiver_address": receivers[0],
            "target_game_object_candidates": _nonzero(fields.get("target-game-object")),
            "owner_entity_candidates": _nonzero(fields.get("owner-entity")),
            "previous_game_object_candidates": _nonzero(fields.get("previous-game-object")),
            "stages": candidate.get("stages", {}),
            "native_receiver_consumption": native[type_index],
        })
    direct = {row["receiver_address"] for row in rows
              if row["native_type_index"] in DIRECT_ANIMATOR_TYPES}
    components = {row["receiver_address"] for row in rows
                  if row["native_type_index"] in COMPONENT_ANIMATOR_TYPES}
    owners = {value for row in rows for value in row["owner_entity_candidates"]}
    return {
        "behavior_tree_address": address,
        "root_tree": "Behavior_Avatar_RemielleOrigin_Decision",
        "task_receivers": rows,
        "native_receiver_contracts": native,
        "summary": {
            "matched_task_contexts": len(rows),
            "direct_animator_tasks": sum(row["native_type_index"] in DIRECT_ANIMATOR_TYPES
                                         for row in rows),
            "component_animator_tasks": sum(row["native_type_index"] in COMPONENT_ANIMATOR_TYPES
                                            for row in rows),
            "unique_direct_animator_addresses": len(direct),
            "unique_animator_component_addresses": len(components),
            "unique_trigger_owner_entities": len(owners),
            "direct_animator_address": next(iter(direct)) if len(direct) == 1 else None,
            "animator_component_address": next(iter(components)) if len(components) == 1 else None,
            "trigger_owner_entity": next(iter(owners)) if len(owners) == 1 else None,
        },
    }


def derive(task_join_path: Path, lifecycle_path: Path, authority_path: Path,
           output: Path) -> dict[str, Any]:
    task_join_path, lifecycle_path, authority_path, output = (
        Path(value).resolve() for value in
        (task_join_path, lifecycle_path, authority_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    result = analyze(_load(task_join_path), _load(lifecycle_path), _load(authority_path))
    document = {
        "schema": "uc.task-receiver-runtime-join.v1",
        "sources": {
            "task_context_static_join": {"path": str(task_join_path), "sha256": file_hash(task_join_path)},
            "field_lifecycle": {"path": str(lifecycle_path), "sha256": file_hash(lifecycle_path)},
            "native_task_consumption": {"path": str(authority_path), "sha256": file_hash(authority_path)},
        },
        **result,
        "semantic_limits": [
            "The common receiver addresses are current-process ObservedAddress evidence, not persistent identities.",
            "The game Animator component is not automatically identical to its nested UnityEngine.Animator field.",
            "A marked action window does not attribute an individual task to one move step.",
            "Parameter hashes were sampled at callback entry before initialization and remain unpromoted when zero.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    report = {"ok": True, "output": str(output), **document["summary"]}
    print(json.dumps(report, ensure_ascii=False))
    return document


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-join", type=Path, required=True)
    parser.add_argument("--field-lifecycle", type=Path, required=True)
    parser.add_argument("--native-authority", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.task_join, args.field_lifecycle, args.native_authority, args.out)


if __name__ == "__main__":
    run_main(main)
