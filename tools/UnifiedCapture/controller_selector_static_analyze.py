"""Recover Remielle random-weight selector branches from authoritative static and runtime joins."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


TREE = "Behavior_Avatar_RemielleOrigin_Confrontation"
TYPE = "MoleMole.RandomExcuteWithSharedWeight"
SELECTOR_INDICES = (3, 45)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _verify_layout(path: Path) -> None:
    text = path.read_text(encoding="utf-8-sig", errors="strict")
    pattern = (r"RandomExcuteWithSharedWeight\s*:\s*Composite\s*\{.*?"
               r"childNodeWeightList;\s*//\s*0x60.*?"
               r"_excuteIndex;\s*//\s*0x68.*?"
               r"seed;\s*//\s*0x6c.*?"
               r"executionStatus;\s*//\s*0x70.*?"
               r"useSeed;\s*//\s*0x74")
    if re.search(pattern, text, re.S) is None:
        raise ValueError("RandomExcuteWithSharedWeight field layout proof is incomplete")


def _weights(task: dict[str, Any]) -> list[dict[str, Any]]:
    fields = task["fields"]
    rows = []
    for pos, field in enumerate(fields):
        name = field.get("mechanicalUtf8")
        if not isinstance(name, str) or not name.startswith("Weight_AIMoveType"):
            continue
        value = next((candidate.get("mechanicalFloat32LE") for candidate in fields[pos + 1:pos + 4]
                      if isinstance(candidate.get("mechanicalFloat32LE"), (int, float))), None)
        if value is None:
            raise ValueError(f"serialized weight value is absent after {name}")
        rows.append({"shared_name": name, "serialized_value": value,
                     "name_field_index": field["fieldIndex"]})
    return rows


def run(native_trees_path: Path, runtime_join_path: Path, type_layout_path: Path,
        output: Path) -> dict[str, Any]:
    native_trees_path, runtime_join_path, type_layout_path, output = [path.resolve() for path in (
        native_trees_path, runtime_join_path, type_layout_path, output)]
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    native, runtime = _load(native_trees_path), _load(runtime_join_path)
    if native.get("schema") != "zzz.remielle.native-external-behavior-trees.v1":
        raise ValueError("unsupported native BehaviorTree authority")
    if runtime.get("schema") != "zzz.native-task-structural-join.v1":
        raise ValueError("unsupported runtime task structural join")
    if not runtime.get("dataIntegrityVerified") or not runtime.get("abTaskJoinComplete"):
        raise ValueError("runtime task structural join is incomplete")
    if runtime.get("authority", {}).get("inputs", {}).get("static", {}).get("sha256", "").lower() != file_hash(native_trees_path):
        raise ValueError("runtime task join was not derived from supplied native trees")
    _verify_layout(type_layout_path)

    tree = next(row for row in native["trees"] if row["name"] == TREE)
    mappings = {(row["abTree"], row["abIndex"]): row for row in runtime["taskMappings"]}
    edges = {(row["parentRuntimeIndex"], row["childRuntimeIndex"]): row
             for row in runtime["observedDispatchEdges"]}
    selectors = []
    for index in SELECTOR_INDICES:
        task = tree["tasks"][index]
        if task["index"] != index or task["type"] != TYPE or len(task["childIndices"]) != 2:
            raise ValueError(f"unexpected selector structure at task {index}")
        mapping = mappings[(TREE, index)]
        if mapping["abType"] != TYPE:
            raise ValueError(f"runtime mapping type mismatch at task {index}")
        branches = []
        for ordinal, child_index in enumerate(task["childIndices"]):
            child = tree["tasks"][child_index]
            child_mapping = mappings[(TREE, child_index)]
            edge = edges.get((mapping["runtimeIndex"], child_mapping["runtimeIndex"]))
            branches.append({
                "ordinal": ordinal,
                "serialized_child_index": child_index,
                "serialized_child_type": child["type"],
                "runtime_child_index": child_mapping["runtimeIndex"],
                "observed_dispatch_count": 0 if edge is None else edge["count"],
                "first_witness": None if edge is None else edge["firstWitness"],
                "last_witness": None if edge is None else edge["lastWitness"],
                "agrees_with_loader_graph": False if edge is None else edge["agreesWithLoaderGraph"],
            })
        weights = _weights(task)
        if len(weights) != 2 or any(row["serialized_value"] != 1.0 for row in weights):
            raise ValueError(f"unexpected serialized selector weights at task {index}")
        selectors.append({
            "serialized_tree": TREE,
            "serialized_task_index": index,
            "runtime_task_index": mapping["runtimeIndex"],
            "runtime_task_pointer": mapping["taskPointer"],
            "run_call_count": mapping["runCallCount"],
            "weights": weights,
            "branches": branches,
            "both_serialized_children_observed": all(row["observed_dispatch_count"] > 0
                                                     for row in branches),
        })
    if not all(row["both_serialized_children_observed"] for row in selectors):
        raise ValueError("both selector outcomes were not observed for every scoped node")

    result = {
        "schema": "uc.controller-selector-static-runtime-join.v1",
        "sources": {"native_behavior_trees": _source(native_trees_path),
                    "runtime_task_structural_join": _source(runtime_join_path),
                    "runtime_type_layout": _source(type_layout_path)},
        "root": {"external_name": runtime["root"]["externalName"],
                 "owner_name": runtime["root"]["ownerName"],
                 "legacy_observer_entity_id": runtime["root"]["entityID"],
                 "identity_level": "ObjectCandidate/structural runtime-to-serialized join"},
        "field_layout": {"child_node_weight_list": 0x60, "execute_index": 0x68,
                         "seed": 0x6C, "execution_status": 0x70, "use_seed": 0x74},
        "selectors": selectors,
        "checks": {"native_raw_reparse_authority": True,
                   "runtime_data_integrity_verified": True,
                   "runtime_to_serialized_task_join_complete": True,
                   "two_remielle_confrontation_selectors": True,
                   "both_children_observed_for_each_selector": True,
                   "selector_choice_edges_closed": True},
        "limits": {
            "execute_index_field_value_observed": False,
            "runtime_serialized_asset_identity_read_directly": False,
            "entity_identity_promoted": False,
            "note": "Observed parent-child RunTask edges prove both branch choices in the structurally joined loaded root; they do not manufacture a direct runtime CAB/PathID read or EntityIdentity.",
        },
        "scope": {"claim": "two Remielle Origin Confrontation random-weight selector outcomes",
                  "no_new_selector_runtime_capture_required": True,
                  "complete_controller": False},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(result))
    print(json.dumps({"schema": result["schema"], "output": _source(output),
                      "selectors": len(selectors),
                      "observed_branch_edges": sum(len(row["branches"]) for row in selectors),
                      "closed": True}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-trees", type=Path, required=True)
    parser.add_argument("--runtime-join", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def execute() -> dict[str, Any]:
        try:
            return run(args.native_trees, args.runtime_join, args.type_layout, args.out)
        except Exception as error:
            write_failure(args.out, "controller_selector_static_analyze", error,
                          {"native_trees": str(args.native_trees),
                           "runtime_join": str(args.runtime_join),
                           "type_layout": str(args.type_layout)})
            raise
    run_main(execute)
