"""Join retained task callbacks to BehaviorTree/index context and static task tables.

The register interpretation is admitted only when the captured callback has a
source-identified BehaviorManager.PushTask or BehaviorManager.RunTask caller.
Static tree identity is reported only when the observed (runtime index, native
type index) signature has a unique superset match in the supplied game-derived
task links.  Runtime indices belong to the expanded root tree instance, so
referenced serialized subtrees are grouped by their game-derived route root.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Any, Iterable

from field_lifecycle_analyze import stable_intervals
from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.store import decode_chunk_file, event_dictionary_context, read_manifest


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _interval(qpc: int, intervals: list[dict[str, Any]]) -> str | None:
    for row in intervals:
        if row["begin_qpc_exclusive"] < qpc < row["end_qpc_exclusive"]:
            return row["label"]
    return None


def _read_value(event: dict[str, Any], name: str) -> int | None:
    for row in event.get("reads", []):
        if row.get("id") == name and row.get("status") == 1 and type(row.get("value")) is int:
            return int(row["value"])
    return None


def _caller_methods(join: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for row in join.get("runtime_callsite_rows", []):
        for method in row.get("caller_method_identities", []):
            result[row["callee_point"]].add(f'{method["owner"]}::{method["method"]}')
    return result


def _root_tree(link: dict[str, Any]) -> str:
    route = link.get("route", [])
    if isinstance(route, list) and route and isinstance(route[0], dict):
        root = route[0].get("fromTree")
        if isinstance(root, str) and root:
            return root
    tree = link.get("abTree")
    if not isinstance(tree, str) or not tree:
        raise ValueError("static task link lacks an authoritative tree identity")
    return tree


def analyze_events(events: Iterable[dict[str, Any]], intervals: list[dict[str, Any]],
                   type_by_point: dict[str, int], caller_join: dict[str, Any],
                   static_links: list[dict[str, Any]], generation: int) -> dict[str, Any]:
    callers = _caller_methods(caller_join)
    contexts: dict[tuple[int, int, int], dict[str, Any]] = {}
    rejected = []
    for event in events:
        if int(event.get("generation", -1)) != generation:
            continue
        point = str(event.get("point", ""))
        type_index = type_by_point.get(point)
        if type_index is None:
            continue
        stem = point.split("@", 1)[0]
        method = stem.rsplit(".", 1)[-1]
        registers = event.get("raw_abi", {}).get("registers", {})
        if method == "OnStart" and "BehaviorManager::PushTask" in callers.get(point, set()):
            tree, task_index = registers.get("rdi"), registers.get("rsi")
            register_contract = "PushTask: RDI=BehaviorTree, ESI=taskIndex"
        elif method == "OnUpdate" and "BehaviorManager::RunTask" in callers.get(point, set()):
            tree, task_index = registers.get("rsi"), registers.get("rbx")
            register_contract = "RunTask: RSI=BehaviorTree, EBX=taskIndex"
        else:
            rejected.append({"event_id": event.get("event_id"), "point": point,
                             "reason": "source_identified_caller_contract_absent"})
            continue
        if type(tree) is not int or type(task_index) is not int:
            rejected.append({"event_id": event.get("event_id"), "point": point,
                             "reason": "required_raw_register_absent"})
            continue
        task_index &= 0xffffffff
        task_address = _read_value(event, "raw-rcx")
        key = (int(tree), task_index, type_index)
        row = contexts.setdefault(key, {
            "behavior_tree_address": int(tree),
            "runtime_task_index": task_index,
            "native_type_index": type_index,
            "points": set(),
            "task_addresses": set(),
            "stages": defaultdict(int),
            "event_ids": [],
            "register_contracts": set(),
        })
        row["points"].add(point)
        if task_address is not None:
            row["task_addresses"].add(task_address)
        stage = _interval(int(event["qpc"]), intervals)
        if stage is not None:
            row["stages"][stage] += 1
        row["event_ids"].append(int(event["event_id"]))
        row["register_contracts"].add(register_contract)

    observed = []
    pairs_by_address: dict[int, set[tuple[int, int]]] = defaultdict(set)
    for key in sorted(contexts):
        row = contexts[key]
        pairs_by_address[row["behavior_tree_address"]].add(
            (row["runtime_task_index"], row["native_type_index"]))
        observed.append({**row,
            "points": sorted(row["points"]),
            "task_addresses": sorted(row["task_addresses"]),
            "stages": dict(sorted(row["stages"].items())),
            "event_ids": sorted(row["event_ids"]),
            "register_contracts": sorted(row["register_contracts"]),
        })

    static_pairs: dict[str, set[tuple[int, int]]] = defaultdict(set)
    static_rows: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for link in static_links:
        if type(link.get("runtimeIndex")) is not int or type(link.get("nativeTypeIndex")) is not int:
            continue
        tree = _root_tree(link)
        pair = (int(link["runtimeIndex"]), int(link["nativeTypeIndex"]))
        static_pairs[tree].add(pair)
        static_rows[(tree, *pair)].append({
            "serialized_subtree": link.get("abTree"),
            "serialized_task_index": link.get("abIndex"),
            "route": link.get("route", []),
            "parameter_name": link.get("parameterName"),
            "type": link.get("type"),
            "raw_field": link.get("rawField"),
            "static_value_fields": link.get("staticValueFields", []),
            "current_parameter_record": link.get("currentParameterRecord"),
            "current_condition_references": link.get("currentConditionReferences", []),
            "static_parameter_targets": link.get("staticParameterTargets", []),
            "source_raw": link.get("sourceRaw"),
            "source_raw_sha256": link.get("sourceRawSha256"),
            "exact_name_join": link.get("exactNameJoin"),
            "source_version_evidence": link.get("sourceVersionEvidence"),
            "live_tree_selection_proven": link.get("liveTreeSelectionProven"),
        })

    trees = []
    for address, pairs in sorted(pairs_by_address.items()):
        candidates = sorted(tree for tree, known in static_pairs.items() if pairs <= known)
        matches = []
        for tree in candidates:
            matches.append({"root_tree": tree, "matched_tasks": [
                {"runtime_task_index": index, "native_type_index": type_index,
                 "static_rows": static_rows[(tree, index, type_index)]}
                for index, type_index in sorted(pairs)
            ]})
        trees.append({
            "behavior_tree_address": address,
            "observed_task_signature": [
                {"runtime_task_index": index, "native_type_index": type_index}
                for index, type_index in sorted(pairs)],
            "candidate_static_trees": matches,
            "identity_status": (
                "UNIQUE_STATIC_TASK_SIGNATURE_MATCH" if len(matches) == 1 else
                "AMBIGUOUS_STATIC_TASK_SIGNATURE_MATCH" if matches else
                "NO_STATIC_TASK_SIGNATURE_MATCH"),
        })
    return {
        "contexts": observed,
        "behavior_trees": trees,
        "rejected_events": rejected,
        "summary": {
            "task_contexts": len(observed),
            "behavior_tree_addresses": len(trees),
            "unique_static_tree_matches": sum(
                row["identity_status"] == "UNIQUE_STATIC_TASK_SIGNATURE_MATCH" for row in trees),
            "ambiguous_static_tree_matches": sum(
                row["identity_status"] == "AMBIGUOUS_STATIC_TASK_SIGNATURE_MATCH" for row in trees),
            "unmatched_tree_addresses": sum(
                row["identity_status"] == "NO_STATIC_TASK_SIGNATURE_MATCH" for row in trees),
            "rejected_events": len(rejected),
        },
    }


def derive(session: Path, checkpoint_path: Path, plan_path: Path,
           caller_join_path: Path, static_links_path: Path, output: Path) -> dict[str, Any]:
    paths = [Path(value).resolve() for value in
             (session, checkpoint_path, plan_path, caller_join_path, static_links_path, output)]
    session, checkpoint_path, plan_path, caller_join_path, static_links_path, output = paths
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    checkpoints, plan, caller_join, static_links = map(
        _load, (checkpoint_path, plan_path, caller_join_path, static_links_path))
    intervals = stable_intervals(checkpoints)
    if not intervals or not all(row["complete"] for row in intervals):
        raise ValueError("checkpoint intervals are incomplete")
    type_by_point = {}
    for row in plan.get("points", []):
        authority = row.get("field_read_contract", {}).get("authority", {})
        if type(authority.get("type_id")) is int:
            type_by_point[row["id"] + "/entry"] = int(authority["type_id"])
    manifest_path = session / "session.manifest"
    manifest, errors = read_manifest(manifest_path)
    if errors:
        raise ValueError(f"manifest errors: {errors}")
    context = event_dictionary_context(manifest_path, manifest)
    session_row = next(row for row in manifest if row.get("kind") == "session")
    generations = {int(point["generation"]) for interval in checkpoints["intervals"]
                   for point in interval.get("points", [])}
    if len(generations) != 1:
        raise ValueError("checkpoint deltas do not identify one generation")
    generation = generations.pop()

    def events():
        for chunk in manifest:
            if chunk.get("kind") != "chunk":
                continue
            _, records = decode_chunk_file(session / chunk["file"], dictionary_context=context)
            for _, _, event, _ in records:
                yield event

    analysis = analyze_events(events(), intervals, type_by_point, caller_join,
                              static_links, generation)
    document = {
        "schema": "uc.task-context-static-join.v1",
        "sources": {
            "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
            "checkpoint_deltas": {"path": str(checkpoint_path), "sha256": file_hash(checkpoint_path)},
            "capture_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
            "controller_caller_join": {"path": str(caller_join_path), "sha256": file_hash(caller_join_path)},
            "static_task_links": {"path": str(static_links_path), "sha256": file_hash(static_links_path)},
        },
        "session_id": session_row["session_id"],
        "generation": generation,
        **analysis,
        "semantic_limits": [
            "A unique static signature match identifies the expanded serialized root BehaviorTree layout, not an EntityIdentity.",
            "User stage labels do not attribute a task to one move.",
            "Task addresses remain ObservedAddress/ObjectCandidate evidence.",
            "Static links retain their own source-version and exact-name limitations.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    result = {"ok": True, "output": str(output), **document["summary"]}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--checkpoints", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--caller-join", type=Path, required=True)
    parser.add_argument("--static-links", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.session, args.checkpoints, args.plan, args.caller_join,
                  args.static_links, args.out)


if __name__ == "__main__":
    run_main(main)
