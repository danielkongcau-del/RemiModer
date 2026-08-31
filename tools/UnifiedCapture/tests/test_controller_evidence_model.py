from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_evidence_model import project


def _graph() -> dict:
    return {
        "schema": "uc.controller-native-evidence-graph.v1",
        "summary": {"nodes": 6},
        "scope": {"accepted_native_leaf": "module+rva+contract"},
        "interpretation_limits": [],
        "graph": {
            "nodes": [
                {"id": "behavior:inventory", "kind": "BEHAVIOR_GRAPH_SUMMARY",
                 "summary": {"trees": 1}},
                {"id": "events:animator-bindings",
                 "kind": "ANIMATOR_EVENT_BINDING_SUMMARY", "summary": {"bindings": 1}},
                {"id": "animator-controller:a", "kind": "ANIMATOR_CONTROLLER",
                 "name": "a", "layers": 1, "states": 2, "transitionRecords": 1,
                 "selectorEdges": 1, "parameters": 1, "rawSha256": "0" * 64,
                 "source": "a.json"},
                {"id": "ability:a", "kind": "ABILITY_ASSET", "name": "a",
                 "source": {"path": "ability.json", "size": 1, "sha256": "1" * 64}},
                {"id": "endpoint-contract:1", "kind": "STATIC_DYNAMIC_ENDPOINT_CONTRACT",
                 "caller_type": "T", "caller_method": "M", "contract": {"kind": "vtable"},
                 "human_readable_callee_name_required": False},
            ],
            "edges": [{"source": "x", "relation": "SERIALIZED_OUTPUT_REFERENCE",
                       "target": "output:animator"}],
        },
    }


def test_projection_is_explicitly_non_executable_and_preserves_unknown_policy() -> None:
    source = {"path": "graph.json", "size": 5, "sha256": "a" * 64}
    completion_source = {"path": "state.json", "size": 6, "sha256": "b" * 64}
    completion = {
        "schema": "uc.controller-completion-state.v1",
        "sources": {"native_evidence_graph": source},
        "claims": [{"id": "C01", "status": "CLOSED"}],
        "acceptance": {"definition_acquisition_complete": True,
                       "runtime_required_now": False},
    }
    model = project(_graph(), completion, source, completion_source)
    assert model["execution_contract"]["executable"] is False
    assert model["execution_contract"]["predictive_defaults"] is False
    assert model["query_policy"]["missing_relation"] == "UNKNOWN"
    assert model["output_reference_index"] == {"animator": ["x"]}


def test_projection_rejects_a_completion_state_for_another_graph() -> None:
    source = {"path": "graph.json", "size": 5, "sha256": "a" * 64}
    completion = {
        "schema": "uc.controller-completion-state.v1",
        "sources": {"native_evidence_graph": {**source, "sha256": "c" * 64}},
        "claims": [], "acceptance": {},
    }
    with pytest.raises(ValueError, match="different graph"):
        project(_graph(), completion, source,
                {"path": "state.json", "size": 1, "sha256": "b" * 64})
