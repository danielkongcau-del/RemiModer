"""Create a read-only Remielle controller evidence projection.

The projection is an index over the immutable native evidence graph.  It is
not executable, does not synthesize missing transitions, and never substitutes
research labels for original game identities.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def project(graph: dict[str, Any], completion: dict[str, Any],
            graph_source: dict[str, Any], completion_source: dict[str, Any]) -> dict[str, Any]:
    if graph.get("schema") != "uc.controller-native-evidence-graph.v1":
        raise ValueError("unsupported native evidence graph")
    if completion.get("schema") != "uc.controller-completion-state.v1":
        raise ValueError("unsupported completion state")
    bound_graph = completion["sources"]["native_evidence_graph"]
    if (bound_graph["sha256"] != graph_source["sha256"]
            or bound_graph["size"] != graph_source["size"]):
        raise ValueError("completion state is bound to a different graph")

    nodes = graph["graph"]["nodes"]
    edges = graph["graph"]["edges"]
    controllers = sorted(
        ({key: row[key] for key in (
            "id", "name", "layers", "states", "transitionRecords",
            "selectorEdges", "parameters", "rawSha256", "source")}
         for row in nodes if row["kind"] == "ANIMATOR_CONTROLLER"),
        key=lambda row: row["name"])
    abilities = sorted(
        ({"id": row["id"], "name": row["name"], "source": row["source"]}
         for row in nodes if row["kind"] == "ABILITY_ASSET"),
        key=lambda row: row["name"])
    behavior = next(row for row in nodes if row["id"] == "behavior:inventory")
    events = next(row for row in nodes if row["id"] == "events:animator-bindings")
    endpoints = sorted(
        ({"id": row["id"], "caller_type": row["caller_type"],
          "caller_method": row["caller_method"], "contract": row["contract"],
          "human_readable_callee_name_required": row[
              "human_readable_callee_name_required"]}
         for row in nodes if row["kind"] == "STATIC_DYNAMIC_ENDPOINT_CONTRACT"),
        key=lambda row: row["id"])
    output_edges = [row for row in edges
                    if row["relation"] == "SERIALIZED_OUTPUT_REFERENCE"]
    outputs: dict[str, list[str]] = {}
    for edge in output_edges:
        family = edge["target"].removeprefix("output:")
        outputs.setdefault(family, []).append(edge["source"])
    outputs = {key: sorted(set(value)) for key, value in sorted(outputs.items())}
    statuses = {row["id"]: row["status"] for row in completion["claims"]}

    return {
        "schema": "uc.controller-evidence-model.v1",
        "identity": "Remielle Origin",
        "model_kind": "READ_ONLY_NATIVE_EVIDENCE_PROJECTION",
        "sources": {
            "native_evidence_graph": graph_source,
            "completion_state": completion_source,
        },
        "execution_contract": {
            "executable": False,
            "predictive_defaults": False,
            "unknown_transition_synthesis": False,
            "original_name_invention": False,
            "authoritative_graph": graph_source,
        },
        "completion": {
            "definition_acquisition_complete": completion["acceptance"][
                "definition_acquisition_complete"],
            "core_claim_statuses": {key: statuses[key]
                                    for key in sorted(statuses) if key.startswith("C")},
            "runtime_required_now": completion["acceptance"]["runtime_required_now"],
        },
        "serialized_roots": {
            "animator_controllers": controllers,
            "behavior": behavior["summary"],
            "abilities": abilities,
            "animator_event_bindings": events["summary"],
        },
        "native_boundary": {
            "summary": graph["summary"],
            "static_dynamic_endpoint_contracts": endpoints,
            "accepted_opaque_leaf": graph["scope"]["accepted_native_leaf"],
        },
        "output_reference_index": outputs,
        "query_policy": {
            "missing_relation": "UNKNOWN",
            "opaque_relation": "return exact identity and contract without semantic expansion",
            "negative_runtime_claim": "requires an independently complete covered window and a sufficient observation point",
        },
        "interpretation_limits": graph["interpretation_limits"] + [
            "this projection indexes acquired evidence and cannot drive a character or predict an unrecorded opaque decision",
            "ability files remain authoritative source documents; the projection references rather than rewrites their serialized contents",
        ],
    }


def build(graph_path: Path, completion_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    graph = _load(graph_path)
    completion = _load(completion_path)
    graph_source = _source(graph_path)
    completion_source = _source(completion_path)
    model = project(graph, completion, graph_source, completion_source)
    out.mkdir(parents=True)
    model_path = out / "remielle-controller-evidence-model.json"
    model_path.write_bytes(canonical(model))
    report = {
        "schema": "uc.controller-evidence-model-report.v1",
        "model": _source(model_path),
        "definition_acquisition_complete": model["completion"][
            "definition_acquisition_complete"],
        "animator_controllers": len(model["serialized_roots"][
            "animator_controllers"]),
        "abilities": len(model["serialized_roots"]["abilities"]),
        "static_dynamic_endpoint_contracts": len(model["native_boundary"][
            "static_dynamic_endpoint_contracts"]),
        "executable": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--completion", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.graph.resolve(), args.completion.resolve(),
                     args.out.resolve())
    except Exception as error:
        write_failure(args.out, "controller_evidence_model", error,
                      {key: str(value) for key, value in vars(args).items()})
        raise


if __name__ == "__main__":
    run_main(main)
