"""Assemble the finite Remielle Origin native-controller evidence graph.

The graph joins authoritative serialized occurrences, harvested IL2CPP classes,
fields and methods, exact native callsites, observed dynamic targets, statically
closed unobserved endpoint contracts, and controller output-reference families.
It is an acquisition package, not a guessed replacement controller.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


OUTPUT_PATTERNS = {
    "animator": ("Animator",),
    "wwise": ("Sound", "Audio", "Wwise"),
    "effect": ("Effect",),
    "camera": ("Camera",),
    "timeline": ("Timeline", "TimeLine"),
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _ability_sources(directory: Path) -> dict[str, dict[str, Any]]:
    rows = {}
    for path in sorted(directory.glob("*.json"), key=lambda value: value.name):
        rows[path.stem] = _source(path)
    if len(rows) != 52:
        raise ValueError(f"expected 52 reconciled Ability assets, got {len(rows)}")
    return rows


def _tree_source(directory: Path, files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    digest = hashlib.sha256(canonical(files)).hexdigest()
    return {"path": str(directory.resolve()), "files": len(files),
            "canonical_manifest_sha256": digest}


def _safe(value: str) -> str:
    return value.replace("%", "%25").replace(":", "%3a")


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[bytes, dict[str, Any]] = {}

    def node(self, node_id: str, kind: str, **properties: Any) -> str:
        row = {"id": node_id, "kind": kind, **properties}
        previous = self.nodes.get(node_id)
        if previous is not None and previous != row:
            raise ValueError(f"conflicting graph node: {node_id}")
        self.nodes[node_id] = row
        return node_id

    def edge(self, source: str, relation: str, target: str, **evidence: Any) -> None:
        row = {"source": source, "relation": relation, "target": target,
               **evidence}
        self.edges[canonical(row)] = row

    def finish(self) -> dict[str, Any]:
        dangling = sorted({edge[key] for edge in self.edges.values()
                           for key in ("source", "target")
                           if edge[key] not in self.nodes})
        if dangling:
            raise ValueError(f"graph contains dangling node ids: {dangling[:5]}")
        nodes = sorted(self.nodes.values(), key=lambda row: row["id"])
        edges = [self.edges[key] for key in sorted(self.edges)]
        return {"nodes": nodes, "edges": edges,
                "validation": {"unique_node_ids": True,
                               "no_dangling_edges": True,
                               "deduplicated_edges": True}}


def _output_families(type_name: str) -> list[str]:
    return [family for family, fragments in OUTPUT_PATTERNS.items()
            if any(fragment in type_name for fragment in fragments)]


def _method_id(type_name: str, method: dict[str, Any]) -> str:
    rva = method.get("rva")
    suffix = f"0x{int(rva):x}" if rva is not None else "no-rva"
    return f"method:{_safe(type_name)}:{_safe(str(method.get('name')))}:{suffix}"


def structural_acceptance(summary: dict[str, Any], graph: dict[str, Any],
                          receiver: dict[str, Any]) -> dict[str, Any]:
    finite = (
        graph.get("validation") == {
            "unique_node_ids": True,
            "no_dangling_edges": True,
            "deduplicated_edges": True,
        }
        and summary["nodes"] == len(graph["nodes"])
        and summary["edges"] == len(graph["edges"])
        and summary["indirect_callsites"] == 353
        and summary["indirect_callsites_with_finite_leaf"] == 353
        and summary["indirect_callsites_without_finite_leaf"] == 0
        and receiver["summary"]["runtime_endpoint_gaps"] == 0
        and receiver["summary"]["static_endpoint_contracts_closed"] == 14
    )
    return {
        "finite_delivery_boundary_satisfied": finite,
        "serialized_native_definition_graph_complete": finite,
        "unobserved_dynamic_endpoint_contracts_complete": (
            receiver["summary"]["runtime_endpoint_gaps"] == 0
            and receiver["summary"]["static_endpoint_contracts_closed"] == 14),
        "runtime_required_for_definition_closure": not finite,
        "human_readable_names_required_for_native_leaf": False,
        "standalone_reimplementation_claimed": False,
        "exhaustive_replay_claimed": False,
        "controller_completion_claimed": False,
        "controller_completion_contract_required": True,
    }


def assemble(inventory: dict[str, Any], ability_files: dict[str, dict[str, Any]],
             coverage: dict[str, Any],
             dynamic_runtime: dict[str, Any], receiver: dict[str, Any],
             indirect_join: dict[str, Any], slot_consumers: dict[str, Any],
             slot_module: dict[str, Any],
             closure: dict[str, Any], boundary: dict[str, Any],
             special: dict[str, Any]) -> dict[str, Any]:
    graph = Graph()
    root = graph.node("controller:RemielleOrigin", "CONTROLLER_ROOT",
                      identity="Remielle Origin",
                      identity_scope="authoritative serialized and native evidence")
    for family in OUTPUT_PATTERNS:
        graph.node(f"output:{family}", "OUTPUT_CHANNEL_REFERENCE_FAMILY",
                   family=family,
                   execution_implementation_included=False)

    graph.node("behavior:inventory", "BEHAVIOR_GRAPH_SUMMARY",
               summary=inventory["behavior"])
    graph.edge(root, "HAS_BEHAVIOR_EVIDENCE", "behavior:inventory")
    graph.node("events:animator-bindings", "ANIMATOR_EVENT_BINDING_SUMMARY",
               summary=inventory["events"])
    graph.edge(root, "HAS_EVENT_BINDING_EVIDENCE", "events:animator-bindings")
    graph.edge("events:animator-bindings", "REFERENCES_OUTPUT_FAMILY", "output:animator")
    for controller in inventory["controllers"]:
        node_id = f"animator-controller:{_safe(controller['name'])}"
        graph.node(node_id, "ANIMATOR_CONTROLLER", **controller)
        graph.edge(root, "HAS_ANIMATOR_CONTROLLER", node_id)
        graph.edge(node_id, "REFERENCES_OUTPUT_FAMILY", "output:animator")

    ability_nodes: dict[str, str] = {}
    for ability, source in sorted(ability_files.items()):
        ability_id = graph.node(f"ability:{_safe(ability)}", "ABILITY_ASSET",
                                name=ability, source=source)
        ability_nodes[ability] = ability_id
        graph.edge(root, "HAS_ABILITY_ASSET", ability_id)
    type_inventory = {row["serializedType"]: row
                      for row in inventory["nativeTypeLedger"]}
    if len(type_inventory) != 188:
        raise ValueError("inventory is not the reviewed 188-type scope")
    coverage_types = {row["serialized_type"]: row for row in coverage["types"]}
    if set(type_inventory) != set(coverage_types):
        raise ValueError("inventory and coverage type scopes differ")

    for type_name in sorted(type_inventory):
        inventory_row = type_inventory[type_name]
        type_row = coverage_types[type_name]
        type_id = graph.node(f"serialized-type:{_safe(type_name)}",
                             "SERIALIZED_NATIVE_TYPE",
                             name=type_name, native_role=type_row.get("native_role"),
                             occurrences=int(inventory_row["occurrences"]),
                             identity_evidence_kind=type_row.get("identity_evidence_kind"))
        graph.edge(root, "REACHES_SERIALIZED_TYPE", type_id)
        for position in inventory_row["positions"]:
            ability = str(position["ability"])
            ability_id = ability_nodes.get(ability)
            if ability_id is None:
                raise ValueError(f"serialized occurrence names unknown Ability asset: {ability}")
            occurrence_id = graph.node(
                f"occurrence:{_safe(position['id'])}", "SERIALIZED_OCCURRENCE",
                source_id=position["id"], json_pointer=position["jsonPointer"],
                ability=ability, serialized_type=type_name)
            graph.edge(ability_id, "CONTAINS_OCCURRENCE", occurrence_id)
            graph.edge(occurrence_id, "HAS_NATIVE_TYPE", type_id)

        for class_role, class_name in (("executor", type_row.get("executor_class")),
                                       ("config", type_row.get("config_class"))):
            if not class_name:
                continue
            class_id = graph.node(f"class:{_safe(class_name)}", "IL2CPP_CLASS",
                                  name=class_name)
            graph.edge(type_id, f"MATERIALIZES_{class_role.upper()}_CLASS", class_id)
        for field in type_row.get("executor_fields", []) + type_row.get("config_fields", []):
            owner_id = graph.node(f"class:{_safe(field['class'])}", "IL2CPP_CLASS",
                                  name=field["class"])
            field_id = graph.node(
                f"field:{_safe(field['class'])}:{_safe(field['token'])}",
                "IL2CPP_FIELD", name=field["field"], owner=field["class"],
                token=field["token"], offset=field["offset"],
                materialized_class=field.get("materializedClass"),
                type_kind=field.get("typeKind"))
            graph.edge(owner_id, "DECLARES_FIELD", field_id)

        for family in _output_families(type_name):
            graph.edge(type_id, "SERIALIZED_OUTPUT_REFERENCE", f"output:{family}",
                       basis="authoritative serialized type name")

        for method in type_row.get("methods", []):
            method_id = _method_id(type_name, method)
            body = method.get("body_decode")
            graph.node(method_id, "NATIVE_METHOD",
                       owner_type=type_name, name=method.get("name"),
                       role=method.get("role"), rva=method.get("rva"),
                       boundary_status=method.get("boundary_status"),
                       signature_evidence=method.get("signature_evidence", []),
                       body_boundary=({key: body.get(key) for key in (
                           "begin_rva", "end_rva", "instruction_count",
                           "all_declared_bytes_decoded", "unwind_rva")}
                           if body else None))
            graph.edge(type_id, "HAS_NATIVE_METHOD", method_id)
            if not body:
                continue
            for call in body.get("direct_calls", []):
                callsite_id = graph.node(
                    f"callsite:0x{int(call['site_rva']):x}", "NATIVE_CALLSITE",
                    rva=int(call["site_rva"]), dispatch="DIRECT")
                target_id = graph.node(
                    f"native-entry:0x{int(call['target_rva']):x}", "NATIVE_ENTRY",
                    module="GameAssembly.dll", rva=int(call["target_rva"]),
                    semantic_name_required=False)
                graph.edge(method_id, "CONTAINS_CALLSITE", callsite_id)
                graph.edge(callsite_id, "DIRECT_CALLS", target_id,
                           target_identity_status=call.get("target_identity_status"),
                           target_identities=call.get("target_identities", []))
            for call in body.get("indirect_calls", []):
                callsite_id = graph.node(
                    f"callsite:0x{int(call['site_rva']):x}", "NATIVE_CALLSITE",
                    rva=int(call["site_rva"]), dispatch="INDIRECT",
                    operands=call.get("operands"), bytes=call.get("bytes"))
                graph.edge(method_id, "CONTAINS_CALLSITE", callsite_id)

    if indirect_join["summary"]["indirect_callsites"] != 353:
        raise ValueError("indirect-call classification is not the reviewed 353-site scope")
    indirect_site_ids = set()
    exact_static_classifications = set()
    for call in indirect_join["callsites"]:
        site_rva = int(call["site_rva"])
        callsite_id = f"callsite:0x{site_rva:x}"
        if callsite_id not in graph.nodes:
            raise ValueError(f"indirect classification lacks method callsite: {site_rva:#x}")
        indirect_site_ids.add(callsite_id)
        contract_id = graph.node(
            f"indirect-classification:0x{site_rva:x}",
            "STATIC_INDIRECT_CLASSIFICATION", site_rva=site_rva,
            caller_type=call["caller_type"], caller_method=call["caller_method"],
            dispatch_form=call["dispatch_form"],
            resolution_status=call["resolution_status"],
            operands=call["operands"], slot_rva=call.get("slot_rva"),
            local_dataflow=call.get("local_dataflow"))
        graph.edge(callsite_id, "HAS_STATIC_INDIRECT_CLASSIFICATION", contract_id)
        if call["resolution_status"] == "EXACT_WRAPPER_SLOT_IDENTITY":
            for wrapper in call["wrapper_stub_identities"]:
                wrapper_id = graph.node(
                    f"wrapper:{_safe(wrapper['class'])}:{_safe(wrapper['method'])}:"
                    f"{int(wrapper['ordinal'])}", "AUTHORITATIVE_WRAPPER_IDENTITY",
                    **wrapper)
                graph.edge(contract_id, "RESOLVES_TO_WRAPPER", wrapper_id)
            exact_static_classifications.add(callsite_id)
        elif call["resolution_status"] == "EXACT_STATIC_TARGET_WITHOUT_SEMANTIC_IDENTITY":
            target_rva = int(call["disk_slot"]["target_rva"])
            target_id = graph.node(
                f"native-entry:0x{target_rva:x}", "NATIVE_ENTRY",
                module="GameAssembly.dll", rva=target_rva,
                semantic_name_required=False)
            graph.edge(contract_id, "RESOLVES_TO_STATIC_TARGET", target_id,
                       disk_slot=call["disk_slot"])
            exact_static_classifications.add(callsite_id)

    module_slots = {int(row["slot_rva"]): row for row in slot_module["slots"]}
    slot_resolved_callsites = set()
    for slot in slot_consumers["initialized_slots"]:
        slot_rva = int(slot["slot_rva"])
        slot_id = graph.node(
            f"dispatch-slot:0x{slot_rva:x}", "INITIALIZED_DISPATCH_SLOT",
            slot_rva=slot_rva, slot_identity=slot["slot_identity"],
            stable=slot["stable"], observations=int(slot["observations"]),
            initialization_owner_status=slot["initialization_owner_status"])
        for consumer in slot["static_consumers"]:
            callsite_id = f"callsite:0x{int(consumer['site_rva']):x}"
            if callsite_id not in graph.nodes:
                raise ValueError(f"slot consumer lacks callsite node: {callsite_id}")
            graph.edge(callsite_id, "CALLS_THROUGH_INITIALIZED_SLOT", slot_id,
                       access_form=consumer["access_form"])
            slot_resolved_callsites.add(callsite_id)
        if slot.get("import"):
            imported = slot["import"]
            import_id = graph.node(
                f"pe-import:{_safe(imported['module'])}:{_safe(imported['name'])}",
                "PE_IMPORT", **imported)
            graph.edge(slot_id, "RESOLVES_TO_IMPORT", import_id)
        else:
            module = module_slots.get(slot_rva)
            if module is None:
                raise ValueError(f"non-import initialized slot lacks module target: {slot_rva:#x}")
            target_id = graph.node(
                f"module-entry:{_safe(module['module'])}:0x{int(module['target_rva']):x}",
                "MODULE_NATIVE_ENTRY", module=module["module"],
                rva=int(module["target_rva"]),
                pdata_begin_rva=int(module["pdata_begin_rva"]),
                pdata_end_rva=int(module["pdata_end_rva"]),
                body_sha256=module["body_sha256"],
                semantic_name_required=False)
            graph.edge(slot_id, "RESOLVES_TO_MODULE_TARGET", target_id)

    observed_points = 0
    unobserved_cctor = 0
    for site in dynamic_runtime["dynamic_sites"]:
        represented = site["static_contract"]["represented_callsites"]
        if not isinstance(represented, list):
            represented = [represented]
        if site["observation"] == "OBSERVED":
            observed_points += 1
            for call in represented:
                callsite_id = f"callsite:0x{int(call['site_rva']):x}"
                if callsite_id not in graph.nodes:
                    graph.node(callsite_id, "NATIVE_CALLSITE",
                               rva=int(call["site_rva"]), dispatch="INDIRECT",
                               operands=call.get("operands"))
                for target in site.get("targets", []):
                    if target["classification"] == "GAME_MODULE_RVA":
                        target_id = graph.node(
                            f"native-entry:0x{int(target['rva']):x}", "NATIVE_ENTRY",
                            module="GameAssembly.dll", rva=int(target["rva"]),
                            semantic_name_required=False)
                    else:
                        target_id = graph.node(
                            f"runtime-address:0x{int(target['address']):x}",
                            "OBSERVED_EXTERNAL_ADDRESS",
                            address=int(target["address"]),
                            classification=target["classification"])
                    graph.edge(callsite_id, "OBSERVED_RESOLVED_TO", target_id,
                               point=site["point"], count=int(target["count"]),
                               class_names=site.get("class_names", []))
        elif any(call["caller_method"] == ".cctor" for call in represented):
            unobserved_cctor += 1
            for call in represented:
                if call["caller_method"] != ".cctor":
                    continue
                callsite_id = f"callsite:0x{int(call['site_rva']):x}"
                boundary_id = graph.node(
                    f"engine-static-initializer-boundary:0x{int(call['site_rva']):x}",
                    "ENGINE_STATIC_INITIALIZER_BOUNDARY",
                    caller_type=call["caller_type"], caller_method=call["caller_method"],
                    reason="excluded engine initialization provenance under frozen boundary")
                graph.edge(callsite_id, "TERMINATES_AT_STATIC_INITIALIZER_BOUNDARY",
                           boundary_id)

    if receiver["summary"]["runtime_endpoint_gaps"] != 0:
        raise ValueError("unobserved endpoint provenance still has runtime gaps")
    for site in receiver["sites"]:
        if not site["static_endpoint_contract_closed"]:
            raise ValueError(f"endpoint is not closed: {site['callsite_rva']:#x}")
        callsite_id = f"callsite:0x{int(site['callsite_rva']):x}"
        if callsite_id not in graph.nodes:
            graph.node(callsite_id, "NATIVE_CALLSITE",
                       rva=int(site["callsite_rva"]), dispatch="INDIRECT",
                       operands=site["call_operands"])
        endpoint_id = graph.node(
            f"endpoint-contract:0x{int(site['callsite_rva']):x}",
            "STATIC_DYNAMIC_ENDPOINT_CONTRACT",
            caller_type=site["caller_type"], caller_method=site["caller_method"],
            contract=site["endpoint_contract"],
            human_readable_callee_name_required=False)
        graph.edge(callsite_id, "STATICALLY_RESOLVES_TO_CONTRACT", endpoint_id,
                   evidence_schema=receiver["schema"])

    dynamic_resolved_callsites = {
        edge["source"] for edge in graph.edges.values()
        if edge["relation"] in {"OBSERVED_RESOLVED_TO",
                                "STATICALLY_RESOLVES_TO_CONTRACT",
                                "TERMINATES_AT_STATIC_INITIALIZER_BOUNDARY"}}
    resolved_indirect = (exact_static_classifications | slot_resolved_callsites
                         | dynamic_resolved_callsites)
    unresolved_indirect = sorted(indirect_site_ids - resolved_indirect)
    if unresolved_indirect:
        raise ValueError(f"indirect callsites remain without a finite leaf: "
                         f"{unresolved_indirect[:8]}")

    special_id = graph.node("evidence:ordinary-special-static-closure",
                            "STRUCTURAL_CLOSURE_EVIDENCE",
                            acceptance=special["acceptance"])
    graph.edge(root, "SUPPORTED_BY", special_id)
    for index, claim in enumerate(closure["closed_bounded"], 1):
        claim_id = graph.node(f"closure-claim:{index:02d}", "BOUNDED_CLOSURE_CLAIM",
                              claim=claim)
        graph.edge(root, "SUPPORTED_BY", claim_id)

    finished = graph.finish()
    kind_counts: dict[str, int] = {}
    for node in finished["nodes"]:
        kind_counts[node["kind"]] = kind_counts.get(node["kind"], 0) + 1
    relation_counts: dict[str, int] = {}
    for edge in finished["edges"]:
        relation_counts[edge["relation"]] = relation_counts.get(edge["relation"], 0) + 1
    summary = {
        "nodes": len(finished["nodes"]), "edges": len(finished["edges"]),
        "node_kinds": dict(sorted(kind_counts.items())),
        "edge_relations": dict(sorted(relation_counts.items())),
        "serialized_types": len(type_inventory),
        "serialized_occurrences": sum(len(row["positions"])
                                      for row in type_inventory.values()),
        "ability_assets": len(ability_nodes),
        "closed_bounded_prior_claims": len(closure["closed_bounded"]),
        "observed_dynamic_points": observed_points,
        "statically_closed_unobserved_endpoints": len(receiver["sites"]),
        "excluded_static_initializer_points": unobserved_cctor,
        "indirect_callsites": len(indirect_site_ids),
        "indirect_callsites_with_finite_leaf": len(resolved_indirect & indirect_site_ids),
        "indirect_callsites_without_finite_leaf": len(unresolved_indirect),
    }
    return {"graph": finished, "summary": summary}


def build(inventory_path: Path, ability_dir: Path, coverage_path: Path,
          dynamic_runtime_path: Path,
          receiver_path: Path, closure_path: Path, boundary_path: Path,
          special_path: Path, indirect_join_path: Path,
          slot_consumers_path: Path, slot_module_path: Path,
          out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    inventory = _load(inventory_path)
    ability_files = _ability_sources(ability_dir)
    coverage = _load(coverage_path)
    dynamic_runtime = _load(dynamic_runtime_path)
    receiver = _load(receiver_path)
    indirect_join = _load(indirect_join_path)
    slot_consumers = _load(slot_consumers_path)
    slot_module = _load(slot_module_path)
    closure = _load(closure_path)
    boundary = _load(boundary_path)
    special = _load(special_path)
    expected = [
        (coverage.get("schema"), "uc.ability-executor-coverage-ledger.v1"),
        (dynamic_runtime.get("schema"), "uc.ability-dynamic-dispatch-runtime-analysis.v1"),
        (receiver.get("schema"), "uc.ability-unobserved-receiver-provenance.v1"),
        (indirect_join.get("schema"), "uc.ability-executor-indirect-call-join.v1"),
        (slot_consumers.get("schema"), "uc.ability-initialized-slot-consumer-join.v1"),
        (slot_module.get("schema"), "uc.ability-initialized-slot-module-join.v1"),
        (closure.get("schema"), "uc.controller-closure-state.v1"),
        (boundary.get("schema"), "uc.controller-delivery-boundary.v1"),
        (special.get("schema"), "uc.ordinary-special-static-closure.v1"),
    ]
    if any(actual != required for actual, required in expected):
        raise ValueError(f"unsupported graph source schema: {expected}")
    if not boundary["acceptance"]["finite_boundary_frozen"]:
        raise ValueError("delivery boundary is not frozen")
    assembled = assemble(inventory, ability_files, coverage, dynamic_runtime, receiver,
                         indirect_join, slot_consumers, slot_module,
                         closure, boundary, special)
    sources = {
        "inventory": _source(inventory_path),
        "ability_assets": _tree_source(ability_dir, ability_files),
        "ability_coverage": _source(coverage_path),
        "dynamic_runtime": _source(dynamic_runtime_path),
        "unobserved_receiver_provenance": _source(receiver_path),
        "indirect_call_classification": _source(indirect_join_path),
        "initialized_slot_consumers": _source(slot_consumers_path),
        "initialized_slot_module_targets": _source(slot_module_path),
        "closure_v43": _source(closure_path), "delivery_boundary": _source(boundary_path),
        "ordinary_special_closure": _source(special_path),
    }
    artifact = {
        "schema": "uc.controller-native-evidence-graph.v1",
        "sources": sources,
        "scope": boundary["definition"],
        "summary": assembled["summary"],
        "graph": assembled["graph"],
        "acceptance": structural_acceptance(assembled["summary"],
                                             assembled["graph"], receiver),
        "remaining_nonblocking": boundary["non_blocking_open_items"],
        "interpretation_limits": [
            "the graph preserves native identities, bodies, callsites, fields and observed or statically bounded dynamic endpoints; it does not invent gameplay names for obfuscated leaves",
            "output-channel nodes preserve authoritative serialized reference families and event/controller summaries, not engine output implementations",
            "a complete acquired definition is not a claim that an independently executable replacement controller has already been authored",
        ],
    }
    out.mkdir(parents=True)
    artifact_path = out / "controller-native-evidence-graph.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.controller-native-evidence-graph-report.v1",
        "artifact": _source(artifact_path), "summary": artifact["summary"],
        "acceptance": artifact["acceptance"],
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--ability-dir", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--dynamic-runtime", type=Path, required=True)
    parser.add_argument("--receiver-provenance", type=Path, required=True)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--boundary", type=Path, required=True)
    parser.add_argument("--special", type=Path, required=True)
    parser.add_argument("--indirect-join", type=Path, required=True)
    parser.add_argument("--slot-consumers", type=Path, required=True)
    parser.add_argument("--slot-module", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.inventory.resolve(), args.ability_dir.resolve(),
                     args.coverage.resolve(),
                     args.dynamic_runtime.resolve(), args.receiver_provenance.resolve(),
                     args.closure.resolve(), args.boundary.resolve(),
                     args.special.resolve(), args.indirect_join.resolve(),
                     args.slot_consumers.resolve(), args.slot_module.resolve(),
                     args.out.resolve())
    except Exception as error:
        write_failure(args.out, "controller_native_graph_assemble", error, {
            key: str(value) for key, value in vars(args).items()})
        raise


if __name__ == "__main__":
    run_main(main)
