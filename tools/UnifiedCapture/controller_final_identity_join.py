"""Join one final runtime generation into a bounded Remielle identity chain.

The join is deliberately address- and event-based.  It does not use the
generic Unity object name captured by the lifecycle observer.  A BehaviorTree
address is promoted only when the same session/generation contains both a
native BehaviorManager load-complete boundary and a unique authoritative
Remielle Origin serialized-task signature.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


ROOT_TREE = "Behavior_Avatar_RemielleOrigin_Decision"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def run(final_runtime_path: Path, task_context_path: Path, output: Path) -> dict[str, Any]:
    final_runtime_path = final_runtime_path.resolve()
    task_context_path = task_context_path.resolve()
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")

    runtime = _load(final_runtime_path)
    contexts = _load(task_context_path)
    if runtime.get("schema") != "uc.controller-final-runtime-analysis.v1":
        raise ValueError("unsupported final runtime analysis")
    if contexts.get("schema") != "uc.task-context-static-join.v1":
        raise ValueError("unsupported task context join")
    if runtime.get("session_id") != contexts.get("session_id"):
        raise ValueError("inputs belong to different sessions")
    if runtime.get("generation") != contexts.get("generation"):
        raise ValueError("inputs belong to different activation generations")
    runtime_manifest = runtime.get("sources", {}).get("manifest", {}).get("sha256")
    context_manifest = contexts.get("sources", {}).get("manifest", {}).get("sha256")
    if not runtime_manifest or runtime_manifest != context_manifest:
        raise ValueError("inputs do not share one manifest identity")
    integrity = runtime.get("integrity", {})
    if (integrity.get("store_clean") is not True or integrity.get("lost_events") != 0
            or integrity.get("manifest_errors") != []):
        raise ValueError("final runtime evidence is not lossless and clean")
    if contexts.get("summary", {}).get("rejected_events") != 0:
        raise ValueError("task context join rejected runtime events")
    if contexts.get("summary", {}).get("ambiguous_static_tree_matches") != 0:
        raise ValueError("task context join contains ambiguous static tree identities")

    remielle_trees = []
    for tree in contexts.get("behavior_trees", []):
        candidates = tree.get("candidate_static_trees", [])
        if (tree.get("identity_status") == "UNIQUE_STATIC_TASK_SIGNATURE_MATCH"
                and len(candidates) == 1 and candidates[0].get("root_tree") == ROOT_TREE):
            remielle_trees.append(tree)
    if len(remielle_trees) != 1:
        raise ValueError("expected exactly one uniquely identified Remielle Origin runtime tree")
    tree = remielle_trees[0]
    tree_address = int(tree["behavior_tree_address"])

    lifetimes = [row for row in runtime.get("behavior_lifetimes", [])
                 if int(row.get("behavior_tree_address", -1)) == tree_address]
    if len(lifetimes) != 1:
        raise ValueError("Remielle runtime tree does not have one load-complete lifetime record")
    lifetime = lifetimes[0]
    if not all(type(lifetime.get(key)) is int and lifetime[key] > 0 for key in
               ("load_event_id", "complete_event_id", "behavior_address", "entity_id")):
        raise ValueError("lifecycle record lacks native load-complete identity fields")
    if lifetime["load_event_id"] >= lifetime["complete_event_id"]:
        raise ValueError("lifecycle event ordering is invalid")

    tree_contexts = [row for row in contexts.get("contexts", [])
                     if int(row.get("behavior_tree_address", -1)) == tree_address]
    signature_count = len(tree.get("observed_task_signature", []))
    if len(tree_contexts) != signature_count or signature_count < 2:
        raise ValueError("runtime tree signature and task contexts disagree")
    task_event_ids = sorted({int(event_id) for row in tree_contexts
                             for event_id in row.get("event_ids", [])})
    if not task_event_ids or task_event_ids[0] <= lifetime["complete_event_id"]:
        raise ValueError("Remielle task execution was not observed after load completion")

    adjacency = [row for row in runtime.get("task_consumer_adjacency", [])
                 if int(row.get("task_event_id", -1)) in set(task_event_ids)]
    if any(row.get("same_thread_consecutive_stored_events") is not True for row in adjacency):
        raise ValueError("matched task/consumer evidence is not consecutively recorded")
    receivers = sorted({int(row["receiver"]) for row in adjacency})
    if not adjacency or len(receivers) != 1:
        raise ValueError("Remielle task/consumer events do not identify one Animator receiver")
    receiver = receivers[0]

    checks = {
        "same_session": True,
        "same_activation_generation": True,
        "same_manifest": True,
        "lossless_runtime_store": True,
        "unique_remielle_static_signature": True,
        "tree_address_equals_load_complete_tree": True,
        "native_entity_id_present": True,
        "task_events_after_load_complete": True,
        "matched_task_consumers_one_receiver": True,
    }
    result = {
        "schema": "uc.controller-final-identity-join.v1",
        "sources": {
            "final_runtime_analysis": _source(final_runtime_path),
            "task_context_static_join": _source(task_context_path),
            "tool": _source(Path(__file__).resolve()),
        },
        "session_id": runtime["session_id"],
        "generation": runtime["generation"],
        "checks": checks,
        "identity_chain": {
            "entity_identity": {"native_entity_id": lifetime["entity_id"]},
            "behavior_instance": {
                "behavior_address": lifetime["behavior_address"],
                "load_event_id": lifetime["load_event_id"],
                "load_complete_event_id": lifetime["complete_event_id"],
                "end_boundary": lifetime.get("end_boundary"),
            },
            "behavior_tree_instance": {
                "address": tree_address,
                "authoritative_root_tree": ROOT_TREE,
                "identity_basis": "UNIQUE_STATIC_TASK_SIGNATURE_MATCH",
                "matched_task_signatures": signature_count,
            },
            "task_executor_membership": {
                "contexts": len(tree_contexts),
                "event_ids": task_event_ids,
                "task_addresses": sorted({int(address) for row in tree_contexts
                                          for address in row.get("task_addresses", [])}),
            },
            "animator_receiver_candidate": {
                "address": receiver,
                "same_thread_consecutive_task_consumer_joins": len(adjacency),
                "task_families": sorted({row["task_family"] for row in adjacency}),
                "consumer_operations": sorted({row["consumer_operation"] for row in adjacency}),
            },
        },
        "bounded_conclusions": [
            ("Within this session and activation generation, native entity ID "
             f"{lifetime['entity_id']} owns the load-completed Behavior instance whose tree "
             f"{tree_address:#x} uniquely matches the authoritative Remielle Origin root."),
            (f"The same tree supplies {signature_count} observed TaskExecutor contexts; "
             f"{len(adjacency)} of their executions are immediately followed on the same "
             f"thread by a selected Unity Animator consumer on one receiver {receiver:#x}."),
        ],
        "semantic_limits": [
            "The Behavior instance end boundary is preserved exactly as observed; an unknown end is not manufactured into a destroy event.",
            "The generic captured Unity source name is not used as identity evidence.",
            "Consecutive task/consumer records prove the bounded callback-to-consumer relation, not every asynchronous Ability scheduling edge.",
            "The Animator receiver remains an ObservedAddress until the independent native Animator ownership path is joined in the same generation.",
        ],
        "complete_controller": False,
    }
    output.mkdir(parents=True)
    artifact = output / "controller-final-identity-join.json"
    artifact.write_bytes(canonical(result))
    report = {
        "schema": "uc.controller-final-identity-join-report.v1",
        "artifact": _source(artifact),
        "entity_id": lifetime["entity_id"],
        "behavior_tree_address": tree_address,
        "matched_task_signatures": signature_count,
        "task_consumer_joins": len(adjacency),
        "animator_receiver": receiver,
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--final-runtime-analysis", type=Path, required=True)
    parser.add_argument("--task-context-static-join", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    def invoke():
        try:
            return run(args.final_runtime_analysis, args.task_context_static_join, args.out)
        except Exception as error:
            write_failure(args.out, "controller_final_identity_join", error,
                          {key: str(value) for key, value in vars(args).items()})
            raise

    run_main(invoke)
