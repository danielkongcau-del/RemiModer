"""Compute a finite Remielle Origin controller-acquisition completion state.

This tool deliberately separates three different propositions:

* the native controller definition has been acquired inside a frozen boundary;
* representative runtime traces validate selected relations;
* an independently executable replacement exists.

Only the first proposition is evaluated here.  The denominator is the fixed
CORE_CLAIMS table below; engine implementation details and optional replay
coverage cannot silently add new blocking claims.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


TERMINAL_CORE_STATUSES = {"CLOSED", "CLOSED_OPAQUE"}
ALL_STATUSES = {
    "OPEN", "CLOSED", "CLOSED_OPAQUE", "ENVIRONMENT_UNAVAILABLE",
    "OUT_OF_SCOPE",
}


CORE_CLAIMS = (
    ("C01", "native scope and module identity"),
    ("C02", "Remielle Origin serialized root inventory"),
    ("C03", "Animator state transition and selector topology"),
    ("C04", "Behavior task variable and condition topology"),
    ("C05", "Task Ability and native ownership boundary"),
    ("C06", "runtime instance lifecycle and entity identity"),
    ("C07", "Animator receiver and stage binding"),
    ("C08", "serialized action output contracts"),
    ("C09", "movement attack dodge and special definitions"),
    ("C10", "switching and assist definitions"),
    ("C11", "phase flow and autonomous-action definitions"),
    ("C12", "ultimate and chain definitions"),
    ("C13", "dynamic native endpoint closure"),
    ("C14", "evidence integrity and finite graph closure"),
)


OPTIONAL_CLAIMS = (
    ("V01", "representative action-window causal validation",
     "VALIDATION_OPTIONAL"),
    ("V02", "ordinary special independent runtime demonstration",
     "VALIDATION_OPTIONAL"),
    ("V03", "human-readable names for opaque native leaves",
     "VALIDATION_OPTIONAL"),
    ("V04", "exhaustive per-move call and return pairing",
     "VALIDATION_OPTIONAL"),
    ("E01", "188-type and 353-callsite engine audit",
     "ENGINE_APPENDIX"),
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _bound_source(graph: dict[str, Any], key: str) -> tuple[Path, dict[str, Any]]:
    source = graph["sources"][key]
    path = Path(source["path"])
    if not path.is_file():
        raise FileNotFoundError(f"bound source is absent: {path}")
    actual = _source(path)
    if actual["sha256"] != source["sha256"] or actual["size"] != source["size"]:
        raise ValueError(f"bound source changed: {path}")
    return path, _load(path)


def _claim(claim_id: str, title: str, status: str,
           reason: str, evidence: list[dict[str, Any]],
           facts: dict[str, Any] | None = None,
           scope: str = "CORE_REQUIRED") -> dict[str, Any]:
    if status not in ALL_STATUSES:
        raise ValueError(f"unknown claim status: {status}")
    return {
        "id": claim_id, "title": title, "scope": scope, "status": status,
        "reason": reason, "evidence": evidence, "facts": facts or {},
    }


def _closed_claims(closure: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["claim"]: row for row in closure["closed_bounded"]}


def _require_claims(closed: dict[str, dict[str, Any]], names: list[str]) -> bool:
    return all(name in closed for name in names)


def completion_from_claims(claims: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    core = [row for row in claims if row["scope"] == "CORE_REQUIRED"]
    declared = [row["id"] for row in core]
    expected = [claim_id for claim_id, _ in CORE_CLAIMS]
    if declared != expected:
        raise ValueError("core completion denominator differs from frozen contract")
    open_core = [row["id"] for row in core
                 if row["status"] not in TERMINAL_CORE_STATUSES]
    return not open_core, open_core


def _controller_literals(graph: dict[str, Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    literals: dict[str, int] = {}
    sources = []
    controllers = [node for node in graph["graph"]["nodes"]
                   if node["kind"] == "ANIMATOR_CONTROLLER"]
    for controller in controllers:
        path = Path(controller["source"])
        record = _load(path)
        if record.get("name") != controller["name"]:
            raise ValueError(f"controller record identity differs: {path}")
        if record.get("rawSha256") != controller["rawSha256"]:
            raise ValueError(f"controller raw identity differs: {path}")
        for value in record.get("tos", {}).values():
            text = str(value)
            for token in (
                    "Attack_Normal", "Evade", "Special", "ExSpecial", "Switch",
                    "ParryAid", "BeHitAid", "AssaultAid", "FlyMode", "TimeSlow",
                    "Attack_Burst", "QTE"):
                if token in text:
                    literals[token] = literals.get(token, 0) + 1
        sources.append(_source(path))
    return dict(sorted(literals.items())), sources


def _ability_names(graph: dict[str, Any]) -> list[str]:
    return sorted(node["name"] for node in graph["graph"]["nodes"]
                  if node["kind"] == "ABILITY_ASSET")


def _has_name(names: list[str], fragment: str) -> bool:
    return any(fragment in name for name in names)


def _edge_count(graph: dict[str, Any], relation: str) -> int:
    return int(graph["summary"]["edge_relations"].get(relation, 0))


def evaluate(graph: dict[str, Any], graph_source: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if graph.get("schema") != "uc.controller-native-evidence-graph.v1":
        raise ValueError("unsupported native evidence graph")
    _, closure = _bound_source(graph, "closure_v43")
    _, boundary = _bound_source(graph, "delivery_boundary")
    _, special = _bound_source(graph, "ordinary_special_closure")
    _, receiver = _bound_source(graph, "unobserved_receiver_provenance")
    _, dynamic = _bound_source(graph, "dynamic_runtime")
    _, inventory = _bound_source(graph, "inventory")
    _, coverage = _bound_source(graph, "ability_coverage")
    _, indirect = _bound_source(graph, "indirect_call_classification")
    literals, controller_sources = _controller_literals(graph)
    abilities = _ability_names(graph)
    closed = _closed_claims(closure)
    summary = graph["summary"]
    behavior = inventory["behavior"]["summary"]
    event_summary = inventory["events"]
    controllers = graph["summary"]["node_kinds"].get("ANIMATOR_CONTROLLER", 0)
    claims: list[dict[str, Any]] = []
    graph_ref = [graph_source]

    c01 = (dynamic.get("module", {}).get("name") == "GameAssembly.dll"
           and len(dynamic.get("module", {}).get("sha256", "")) == 64
           and boundary.get("acceptance", {}).get("finite_boundary_frozen") is True)
    claims.append(_claim("C01", CORE_CLAIMS[0][1],
                         "CLOSED" if c01 else "OPEN",
                         "The graph is bound to one hashed GameAssembly image and a frozen delivery boundary."
                         if c01 else "Module identity or the frozen delivery boundary is missing.",
                         graph_ref + [_source(Path(graph["sources"]["dynamic_runtime"]["path"])),
                                      _source(Path(graph["sources"]["delivery_boundary"]["path"]))],
                         {"module": dynamic.get("module"),
                          "finite_boundary_frozen": boundary.get("acceptance", {}).get(
                              "finite_boundary_frozen")}))

    c02 = (controllers == 6 and summary["ability_assets"] == 52
           and behavior["treeCount"] == 7
           and behavior["unresolvedReferenceCount"] == 0)
    claims.append(_claim("C02", CORE_CLAIMS[1][1],
                         "CLOSED" if c02 else "OPEN",
                         "All frozen Remielle Origin serialized roots and their reference edges are present."
                         if c02 else "The frozen serialized-root inventory differs.", graph_ref,
                         {"animator_controllers": controllers,
                          "ability_assets": summary["ability_assets"],
                          "behavior_trees": behavior["treeCount"],
                          "unresolved_behavior_references": behavior[
                              "unresolvedReferenceCount"]}))

    controller_nodes = [node for node in graph["graph"]["nodes"]
                        if node["kind"] == "ANIMATOR_CONTROLLER"]
    topology = {
        "states": sum(int(row["states"]) for row in controller_nodes),
        "transition_records": sum(int(row["transitionRecords"])
                                  for row in controller_nodes),
        "selector_edges": sum(int(row["selectorEdges"]) for row in controller_nodes),
        "parameters": sum(int(row["parameters"]) for row in controller_nodes),
        "unknown_tail_bytes_preserved": sum(int(row["unknownTailBytes"])
                                            for row in controller_nodes),
    }
    c03 = all(topology[key] > 0 for key in (
        "states", "transition_records", "selector_edges", "parameters"))
    claims.append(_claim("C03", CORE_CLAIMS[2][1],
                         "CLOSED_OPAQUE" if c03 else "OPEN",
                         "State, transition, selector and parameter records are acquired; uninterpreted tail bytes remain preserved rather than guessed."
                         if c03 else "Animator topology records are incomplete.",
                         graph_ref + controller_sources, topology))

    required_c04 = [
        "Remielle five serialized condition signatures runtime execution",
        "observed Remielle tasks to serialized ancestor branches",
        "IntComparison serialized operation numeric semantics",
    ]
    c04 = (behavior["taskCount"] == 415 and behavior["variableCount"] == 210
           and _require_claims(closed, required_c04))
    claims.append(_claim("C04", CORE_CLAIMS[3][1],
                         "CLOSED_OPAQUE" if c04 else "OPEN",
                         "Behavior topology and known numeric condition semantics are acquired; six unresolved original field hashes remain opaque identifiers."
                         if c04 else "Behavior topology or condition evidence is missing.",
                         graph_ref, {"tasks": behavior["taskCount"],
                                     "task_types": behavior["taskTypeCount"],
                                     "variables": behavior["variableCount"],
                                     "unresolved_unique_field_hashes": inventory[
                                         "behavior"]["fieldSummary"]["unresolvedUniqueHashes"],
                                     "required_prior_claims": required_c04}))

    c05 = (summary["serialized_types"] == 188
           and summary["serialized_occurrences"] == 2319
           and summary["node_kinds"].get("NATIVE_METHOD") == 996
           and coverage["summary"]["positions_complete_types"] == 188)
    claims.append(_claim("C05", CORE_CLAIMS[4][1],
                         "CLOSED_OPAQUE" if c05 else "OPEN",
                         "Every serialized Ability type and occurrence is joined to its harvested native ownership boundary; obfuscated method names are not invented."
                         if c05 else "Ability occurrence or native ownership coverage is incomplete.",
                         graph_ref, {"serialized_types": summary["serialized_types"],
                                     "serialized_occurrences": summary[
                                         "serialized_occurrences"],
                                     "native_methods": summary["node_kinds"].get(
                                         "NATIVE_METHOD"),
                                     "position_complete_types": coverage["summary"].get(
                                         "positions_complete_types")}))

    required_c06 = [
        "BehaviorManager load-complete-destroy boundaries",
        "native Remielle entity to Behavior instance and authoritative tree identity",
        "Remielle TaskExecutor membership to selected Animator consumer receiver",
        "Remielle native Animator to stage same-instance ownership",
    ]
    c06 = _require_claims(closed, required_c06)
    claims.append(_claim("C06", CORE_CLAIMS[5][1],
                         "CLOSED" if c06 else "OPEN",
                         "One clean generation proves the required entity, Behavior, TaskExecutor and Animator instance relations."
                         if c06 else "A required runtime identity relation is absent.",
                         [_source(Path(graph["sources"]["closure_v43"]["path"]))],
                         {"required_prior_claims": required_c06,
                          "all_present": c06}))

    required_c07 = [
        "native Animator to consumer to stage static ownership path",
        "Remielle TaskExecutor membership to selected Animator consumer receiver",
        "Remielle native Animator to stage same-instance ownership",
    ]
    c07 = _require_claims(closed, required_c07)
    claims.append(_claim("C07", CORE_CLAIMS[6][1],
                         "CLOSED" if c07 else "OPEN",
                         "The Remielle TaskExecutor receiver, native Animator and stage chain are joined by static and same-generation evidence."
                         if c07 else "Animator receiver or stage binding is missing.",
                         [_source(Path(graph["sources"]["closure_v43"]["path"]))],
                         {"required_prior_claims": required_c07,
                          "all_present": c07}))

    output_counts = {}
    for row in graph["graph"]["edges"]:
        if row["relation"] == "SERIALIZED_OUTPUT_REFERENCE":
            family = row["target"].removeprefix("output:")
            output_counts[family] = output_counts.get(family, 0) + 1
    c08 = (event_summary["bindings"] == 198 and sum(output_counts.values()) == 31
           and all(output_counts.get(name, 0) > 0
                   for name in ("animator", "wwise", "effect", "camera", "timeline")))
    claims.append(_claim("C08", CORE_CLAIMS[7][1],
                         "CLOSED_OPAQUE" if c08 else "OPEN",
                         "Serialized output-reference families and Animator event bindings are preserved; engine output implementations are boundary leaves."
                         if c08 else "One or more output-reference families are absent.",
                         graph_ref, {"serialized_output_references": output_counts,
                                     "animator_event_bindings": event_summary["bindings"]}))

    c09 = (all(literals.get(token, 0) > 0
               for token in ("Attack_Normal", "Evade", "Special"))
           and special["acceptance"]["structural_definition_closed"] is True)
    claims.append(_claim("C09", CORE_CLAIMS[8][1],
                         "CLOSED_OPAQUE" if c09 else "OPEN",
                         "Authoritative controller literals cover normal attack, evade and special families, and ordinary/enhanced special branching is structurally closed."
                         if c09 else "A required base-combat action family is absent.",
                         controller_sources + [_source(Path(
                             graph["sources"]["ordinary_special_closure"]["path"]))],
                         {"controller_literal_counts": {key: literals.get(key, 0)
                                                        for key in ("Attack_Normal", "Evade", "Special", "ExSpecial")},
                          "ordinary_special_structural_definition": special[
                              "acceptance"]["structural_definition_closed"]}))

    c10 = (literals.get("Switch", 0) > 0
           and any(literals.get(token, 0) > 0
                   for token in ("ParryAid", "BeHitAid", "AssaultAid"))
           and _has_name(abilities, "AidAttack") and _has_name(abilities, "ParryAid"))
    claims.append(_claim("C10", CORE_CLAIMS[9][1],
                         "CLOSED_OPAQUE" if c10 else "OPEN",
                         "Authoritative controller and Ability assets contain switching, defensive-assist and aid-attack definitions."
                         if c10 else "Switching or assist structural definitions are absent.",
                         graph_ref + controller_sources,
                         {"controller_literal_counts": {key: literals.get(key, 0)
                                                        for key in ("Switch", "ParryAid", "BeHitAid", "AssaultAid")},
                          "ability_name_witnesses": [name for name in abilities
                                                     if "AidAttack" in name or "ParryAid" in name]}))

    c11 = (literals.get("FlyMode", 0) > 0
           and _has_name(abilities, "TimeSlow")
           and _has_name(abilities, "AirMode_BackStage")
           and _has_name(abilities, "UniqueSkill"))
    claims.append(_claim("C11", CORE_CLAIMS[10][1],
                         "CLOSED_OPAQUE" if c11 else "OPEN",
                         "Phase-flow, backstage autonomous-action and unique-skill definitions are present as authoritative controller and Ability records."
                         if c11 else "A phase-flow structural definition is absent.",
                         graph_ref + controller_sources,
                         {"fly_mode_literals": literals.get("FlyMode", 0),
                          "ability_name_witnesses": [name for name in abilities if any(
                              token in name for token in ("TimeSlow", "AirMode_BackStage", "UniqueSkill"))]}))

    c12 = (literals.get("Attack_Burst", 0) > 0 and literals.get("QTE", 0) > 0
           and _has_name(abilities, "EnterCharacterUltPerform")
           and _has_name(abilities, "QTE"))
    claims.append(_claim("C12", CORE_CLAIMS[11][1],
                         "CLOSED_OPAQUE" if c12 else "OPEN",
                         "Authoritative burst/ultimate and QTE/chain definitions are present; opaque native leaves retain exact identities."
                         if c12 else "Ultimate or chain structural definitions are absent.",
                         graph_ref + controller_sources,
                         {"attack_burst_literals": literals.get("Attack_Burst", 0),
                          "qte_literals": literals.get("QTE", 0),
                          "ability_name_witnesses": [name for name in abilities if any(
                              token in name for token in ("EnterCharacterUltPerform", "QTE"))]}))

    c13 = (receiver["summary"]["runtime_endpoint_gaps"] == 0
           and receiver["summary"]["static_endpoint_contracts_closed"] == 14
           and summary["indirect_callsites_without_finite_leaf"] == 0
           and summary["indirect_callsites_with_finite_leaf"] == 353)
    claims.append(_claim("C13", CORE_CLAIMS[12][1],
                         "CLOSED_OPAQUE" if c13 else "OPEN",
                         "All in-scope dynamic endpoints and all reviewed indirect callsites terminate at finite native contracts."
                         if c13 else "A dynamic or indirect native endpoint remains open.",
                         graph_ref + [_source(Path(
                             graph["sources"]["unobserved_receiver_provenance"]["path"]))],
                         {"static_endpoint_contracts_closed": receiver["summary"][
                              "static_endpoint_contracts_closed"],
                          "runtime_endpoint_gaps": receiver["summary"]["runtime_endpoint_gaps"],
                          "indirect_callsites": summary["indirect_callsites"],
                          "finite_leaves": summary["indirect_callsites_with_finite_leaf"]}))

    validation = graph["graph"]["validation"]
    c14 = (all(validation.values()) and summary["nodes"] == len(graph["graph"]["nodes"])
           and summary["edges"] == len(graph["graph"]["edges"])
           and indirect["summary"]["indirect_callsites"] == 353)
    claims.append(_claim("C14", CORE_CLAIMS[13][1],
                         "CLOSED" if c14 else "OPEN",
                         "All graph invariants, source bindings and finite-scope counts validate mechanically."
                         if c14 else "Graph integrity or frozen-scope counts differ.", graph_ref,
                         {"graph_validation": validation, "nodes": summary["nodes"],
                          "edges": summary["edges"],
                          "reviewed_indirect_callsites": indirect["summary"][
                              "indirect_callsites"]}))

    optional = [
        _claim("V01", OPTIONAL_CLAIMS[0][1], "OPEN",
               "Trace conformance is generated separately and cannot block definition acquisition.",
               [], scope=OPTIONAL_CLAIMS[0][2]),
        _claim("V02", OPTIONAL_CLAIMS[1][1], "ENVIRONMENT_UNAVAILABLE",
               "The trial environment did not independently demonstrate ordinary special; its authoritative structural definition is closed by C09.",
               [_source(Path(graph["sources"]["ordinary_special_closure"]["path"]))],
               scope=OPTIONAL_CLAIMS[1][2]),
        _claim("V03", OPTIONAL_CLAIMS[2][1], "CLOSED_OPAQUE",
               "Exact RVA/body/ABI or field contracts are terminal evidence even when original human-readable names are absent.",
               graph_ref, scope=OPTIONAL_CLAIMS[2][2]),
        _claim("V04", OPTIONAL_CLAIMS[3][1], "OPEN",
               "Exhaustive per-move call/return pairing is validation granularity, not a finite definition requirement.",
               [_source(Path(graph["sources"]["closure_v43"]["path"]))],
               scope=OPTIONAL_CLAIMS[3][2]),
        _claim("E01", OPTIONAL_CLAIMS[4][1], "CLOSED",
               "The completed engine audit is retained as supporting evidence outside the controller denominator.",
               graph_ref, {"types": summary["serialized_types"],
                           "indirect_callsites": summary["indirect_callsites"],
                           "finite_leaves": summary["indirect_callsites_with_finite_leaf"]},
               scope=OPTIONAL_CLAIMS[4][2]),
    ]

    complete, open_core = completion_from_claims(claims)
    state = {
        "schema": "uc.controller-completion-state.v1",
        "contract_id": "RemielleOrigin.native-controller-acquisition.v1",
        "definition": "finite authoritative client-side native controller definition acquisition; not an independently executable replacement",
        "sources": {"native_evidence_graph": graph_source},
        "claims": claims + optional,
        "summary": {
            "core_claims": len(claims),
            "core_closed": sum(row["status"] in TERMINAL_CORE_STATUSES for row in claims),
            "core_open": len(open_core),
            "optional_claims": len(optional),
            "open_core_claim_ids": open_core,
        },
        "acceptance": {
            "definition_acquisition_complete": complete,
            "runtime_required_now": not complete,
            "representative_trace_validation_complete": False,
            "independent_reimplementation_complete": False,
        },
        "next_work_policy": {
            "runtime_capture_allowed_only_for_open_core_claim": True,
            "engine_dependency_discovery_adds_core_claim_automatically": False,
            "unknown_semantics_are_never_filled_by_default": True,
        },
    }
    engine = {
        "schema": "uc.controller-engine-audit-appendix.v1",
        "sources": {"native_evidence_graph": graph_source},
        "scope": "supporting engine implementation audit; excluded from controller completion denominator",
        "summary": {
            "serialized_types": summary["serialized_types"],
            "serialized_occurrences": summary["serialized_occurrences"],
            "native_methods": summary["node_kinds"].get("NATIVE_METHOD"),
            "native_callsites": summary["node_kinds"].get("NATIVE_CALLSITE"),
            "direct_calls": _edge_count(graph, "DIRECT_CALLS"),
            "indirect_callsites": summary["indirect_callsites"],
            "indirect_callsites_with_finite_leaf": summary[
                "indirect_callsites_with_finite_leaf"],
            "indirect_callsites_without_finite_leaf": summary[
                "indirect_callsites_without_finite_leaf"],
        },
        "acceptance": {
            "audit_complete": summary["indirect_callsites_without_finite_leaf"] == 0,
            "controller_blocking": False,
            "recursive_helper_semantics_required": False,
        },
        "nonblocking_residuals": boundary["non_blocking_open_items"],
    }
    return state, engine


def build(graph_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    graph = _load(graph_path)
    graph_source = _source(graph_path)
    state, engine = evaluate(graph, graph_source)
    contract = {
        "schema": "uc.controller-completion-contract.v1",
        "contract_id": state["contract_id"],
        "scope": {
            "root": "Remielle Origin",
            "required": "L0 serialized/native controller plus L1 runtime binding sufficient to prove L0 identities",
            "engine_boundary": "L2 helpers terminate at exact interface contracts unless they change an in-scope decision",
        },
        "statuses": sorted(ALL_STATUSES),
        "core_terminal_statuses": sorted(TERMINAL_CORE_STATUSES),
        "core_claims": [{"id": claim_id, "title": title}
                        for claim_id, title in CORE_CLAIMS],
        "optional_claims": [{"id": claim_id, "title": title, "scope": scope}
                            for claim_id, title, scope in OPTIONAL_CLAIMS],
        "completion_rule": {
            "definition_acquisition_complete": "every CORE_REQUIRED claim is CLOSED or CLOSED_OPAQUE",
            "environment_unavailable_is_core_success": False,
            "out_of_scope_is_core_success": False,
            "representative_runtime_replay_required": False,
            "independent_reimplementation_required": False,
        },
    }
    out.mkdir(parents=True)
    contract_path = out / "controller-completion-contract.v1.json"
    state_path = out / "controller-completion-state.json"
    engine_path = out / "controller-engine-audit-appendix.json"
    contract_path.write_bytes(canonical(contract))
    state_path.write_bytes(canonical(state))
    engine_path.write_bytes(canonical(engine))
    report = {
        "schema": "uc.controller-completion-report.v1",
        "contract": _source(contract_path), "state": _source(state_path),
        "engine_audit": _source(engine_path), "summary": state["summary"],
        "acceptance": state["acceptance"],
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.graph.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "controller_completion_contract", error,
                      {key: str(value) for key, value in vars(args).items()})
        raise


if __name__ == "__main__":
    run_main(main)
