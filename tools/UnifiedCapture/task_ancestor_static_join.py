"""Join observed Remielle task signatures to authoritative serialized ancestor chains."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _condition(node: dict[str, Any], field_map: dict[str, Any]) -> dict[str, Any] | None:
    if not str(node.get("type", "")).endswith("ConditionalEvaluator"):
        return None
    result: dict[str, Any] = {}
    for field in node.get("fields", []):
        resolved = field_map.get("resolved", {}).get(str(field.get("fieldNameHash")))
        if not isinstance(resolved, dict):
            continue
        name = resolved.get("fieldName")
        field_type = resolved.get("fieldType")
        prefixes = {row.get("prefixField", {}).get("fieldName")
                    for row in resolved.get("candidates", []) if isinstance(row, dict)}
        for candidate in resolved.get("candidates", []):
            if not isinstance(candidate, dict) or type(candidate.get("hashPrefix")) is not int:
                continue
            prefix = field_map.get("resolved", {}).get(str(candidate["hashPrefix"]), {})
            if isinstance(prefix, dict):
                prefixes.add(prefix.get("fieldName"))
        if name == "conditionalTask":
            result["conditional_task_type"] = field.get("mechanicalUtf8")
        elif name == "operation" and field_type == "Operation":
            result["operation_raw"] = field.get("mechanicalInt32LE")
        elif name == "Name" and "integer1" in prefixes:
            result["integer1_shared_name"] = field.get("mechanicalUtf8")
        elif name == "mValue" and "integer2" in prefixes:
            result["integer2_constant_raw"] = field.get("mechanicalInt32LE")
    return result


def analyze(task_join: dict[str, Any], trees_document: dict[str, Any],
            field_map: dict[str, Any]) -> dict[str, Any]:
    if task_join.get("schema") != "uc.task-context-static-join.v1":
        raise ValueError("unsupported task context join")
    trees = {row["name"]: row for row in trees_document.get("trees", [])}
    matches = [row for row in task_join.get("behavior_trees", [])
               if row.get("identity_status") == "UNIQUE_STATIC_TASK_SIGNATURE_MATCH"]
    if len(matches) != 1 or len(matches[0].get("candidate_static_trees", [])) != 1:
        raise ValueError("one unique runtime tree match is required")
    root = matches[0]["candidate_static_trees"][0]
    if root.get("root_tree") != "Behavior_Avatar_RemielleOrigin_Decision":
        raise ValueError("runtime tree is not Remielle Origin Decision")
    rows = []
    groups: dict[tuple[tuple[str, int], ...], list[int]] = defaultdict(list)
    for task in root.get("matched_tasks", []):
        static_rows = task.get("static_rows", [])
        if len(static_rows) != 1:
            raise ValueError("observed task signature lacks a unique serialized row")
        static = static_rows[0]
        tree_name = static.get("serialized_subtree")
        index = static.get("serialized_task_index")
        if tree_name not in trees or type(index) is not int:
            raise ValueError("serialized tree task location is absent")
        serialized_tasks = trees[tree_name].get("tasks", [])
        if not 0 <= index < len(serialized_tasks):
            raise ValueError("serialized task index is out of range")
        node = serialized_tasks[index]
        if node.get("type") != static.get("type"):
            raise ValueError("serialized task type disagrees with exact static task link")
        ancestors = []
        current = node
        seen = {index}
        while int(current.get("parentIndex", -1)) >= 0:
            parent_index = int(current["parentIndex"])
            if parent_index in seen or parent_index >= len(serialized_tasks):
                raise ValueError("invalid serialized ancestor chain")
            seen.add(parent_index)
            current = serialized_tasks[parent_index]
            ancestors.append({"index": parent_index, "type": current["type"],
                              "child_indices": current.get("childIndices", [])})
        ancestors.reverse()
        conditions = [{"tree": tree_name, "task_index": ancestor["index"],
                       **condition}
                      for ancestor in ancestors
                      if (condition := _condition(serialized_tasks[ancestor["index"]], field_map))]
        branch = tuple((row["type"], row["index"]) for row in ancestors)
        groups[branch].append(int(task["runtime_task_index"]))
        rows.append({
            "runtime_task_index": int(task["runtime_task_index"]),
            "native_type_index": int(task["native_type_index"]),
            "serialized_subtree": tree_name,
            "serialized_task_index": index,
            "serialized_task_type": node["type"],
            "parameter_name": static.get("parameter_name"),
            "static_value_fields": static.get("static_value_fields", []),
            "route": static.get("route", []),
            "ancestor_chain": ancestors,
            "ancestor_conditions": conditions,
        })
    branch_groups = [{
        "serialized_subtree": next(row["serialized_subtree"] for row in rows
                                   if row["runtime_task_index"] in runtime_indices),
        "ancestor_chain": [{"type": type_name, "index": index}
                           for type_name, index in branch],
        "runtime_task_indices": sorted(runtime_indices),
    } for branch, runtime_indices in sorted(groups.items(), key=lambda item: item[1])]
    return {
        "root_tree": root["root_tree"],
        "task_ancestor_rows": rows,
        "branch_groups": branch_groups,
        "summary": {
            "joined_task_signatures": len(rows),
            "serialized_subtrees": len({row["serialized_subtree"] for row in rows}),
            "unique_ancestor_chains": len(branch_groups),
            "conditional_evaluator_nodes": len({
                (row["serialized_subtree"], ancestor["index"])
                for row in rows for ancestor in row["ancestor_chain"]
                if ancestor["type"].endswith("ConditionalEvaluator")}),
            "random_weight_nodes": len({
                (row["serialized_subtree"], ancestor["index"])
                for row in rows for ancestor in row["ancestor_chain"]
                if ancestor["type"] == "MoleMole.RandomExcuteWithSharedWeight"}),
        },
    }


def derive(task_join_path: Path, trees_path: Path, field_map_path: Path,
           output: Path) -> dict[str, Any]:
    task_join_path, trees_path, field_map_path, output = (Path(value).resolve()
        for value in (task_join_path, trees_path, field_map_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    result = analyze(_load(task_join_path), _load(trees_path), _load(field_map_path))
    document = {
        "schema": "uc.task-ancestor-static-join.v1",
        "sources": {
            "task_context_static_join": {"path": str(task_join_path), "sha256": file_hash(task_join_path)},
            "native_behavior_trees": {"path": str(trees_path), "sha256": file_hash(trees_path)},
            "behavior_field_hash_map": {"path": str(field_map_path), "sha256": file_hash(field_map_path)},
        },
        **result,
        "semantic_limits": [
            "Ancestor chains are serialized control structure, not proof that every ancestor executed in one retained callback.",
            "ConditionalEvaluator and random-weight node types do not reveal their runtime outcomes without field or execution evidence.",
            "IntComparison operation values remain raw enum integers unless the native enum mapping is separately recovered.",
            "No move name is assigned from a user checkpoint label.",
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
    parser.add_argument("--trees", type=Path, required=True)
    parser.add_argument("--field-map", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.task_join, args.trees, args.field_map, args.out)


if __name__ == "__main__":
    run_main(main)
