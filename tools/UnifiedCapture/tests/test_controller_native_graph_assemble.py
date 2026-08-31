from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_native_graph_assemble import Graph, _output_families, structural_acceptance


def test_graph_deduplicates_identical_edges_and_rejects_dangling_ids() -> None:
    graph = Graph()
    graph.node("a", "ROOT")
    graph.node("b", "LEAF", value=1)
    graph.edge("a", "HAS", "b")
    graph.edge("a", "HAS", "b")
    result = graph.finish()
    assert len(result["edges"]) == 1
    graph.edge("a", "HAS", "missing")
    with pytest.raises(ValueError, match="dangling"):
        graph.finish()


def test_graph_rejects_conflicting_node_redefinition() -> None:
    graph = Graph()
    graph.node("x", "TYPE", value=1)
    with pytest.raises(ValueError, match="conflicting"):
        graph.node("x", "TYPE", value=2)


def test_output_family_is_lexical_and_multi_family() -> None:
    assert _output_families("HandleAnimatorZoneTagsAction") == ["animator"]
    assert _output_families("AttackCameraShakeEffectAction") == ["effect", "camera"]
    assert _output_families("TriggerSoundAction") == ["wwise"]


def test_structural_acceptance_is_computed_and_does_not_claim_controller_completion() -> None:
    graph = {
        "nodes": [{"id": "n"}], "edges": [],
        "validation": {"unique_node_ids": True, "no_dangling_edges": True,
                       "deduplicated_edges": True},
    }
    summary = {"nodes": 1, "edges": 0, "indirect_callsites": 353,
               "indirect_callsites_with_finite_leaf": 353,
               "indirect_callsites_without_finite_leaf": 0}
    receiver = {"summary": {"runtime_endpoint_gaps": 0,
                            "static_endpoint_contracts_closed": 14}}
    result = structural_acceptance(summary, graph, receiver)
    assert result["serialized_native_definition_graph_complete"] is True
    assert result["controller_completion_claimed"] is False
    assert result["controller_completion_contract_required"] is True
    summary["indirect_callsites_without_finite_leaf"] = 1
    assert structural_acceptance(summary, graph, receiver)[
        "serialized_native_definition_graph_complete"] is False
