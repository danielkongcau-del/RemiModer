"""Join entry-probe runtime callers to source-verified logical native functions.

The entry analyzer deliberately reports the immediate PDATA owner of a return
address.  A logical Windows x64 function may, however, span chained PDATA
fragments.  This tool performs the separate, evidence-bounded join from those
fragment owners to a static logical root and cross-checks each observed callsite
against the audited direct/indirect callsite inventory.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _point_id(function_id: str) -> str:
    return f"{function_id}/entry"


def _root_id(root: int) -> str:
    return f"UnityPlayer.0x{root:x}"


def _frontier_indices(frontier: dict[str, Any]) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    fragments: dict[int, dict[str, Any]] = {}
    calls: dict[int, dict[str, Any]] = {}
    for key, function in frontier.get("functions", {}).items():
        root = int(function.get("rootRva", key), 0) if isinstance(function.get("rootRva", key), str) else int(function.get("rootRva", int(key, 0)))
        for fragment in function.get("fragments", []):
            begin = int(fragment["rva"])
            end = int(fragment.get("declaredEnd", begin))
            fragments[begin] = {"logical_root_rva": root, "fragment_begin_rva": begin,
                                "fragment_end_rva": end, "extent": function.get("extent")}
    for edge in frontier.get("directEdges", []):
        calls[int(edge["rva"])] = {"kind": "direct", "logical_root_rva": int(edge["logicalRoot"], 0),
                                   "target_rva": int(edge["targetRva"], 0), "bytes": edge.get("bytes")}
    for edge in frontier.get("indirectSites", []):
        calls[int(edge["rva"])] = {"kind": "indirect", "logical_root_rva": int(edge["logicalRoot"], 0),
                                   "target_rva": None, "bytes": edge.get("bytes")}
    return fragments, calls


def _catalog(engine_dispatch: dict[str, Any] | None,
             native_consumers: dict[str, Any] | None) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    if engine_dispatch:
        roles = {
            int(engine_dispatch.get("dispatch", {}).get("driverPrimaryRva", -1)): "animator-fixed-update-driver-primary",
            int(engine_dispatch.get("dispatch", {}).get("driverFragmentRva", -1)): "animator-fixed-update-driver-fragment",
            int(engine_dispatch.get("dispatch", {}).get("wrapperRva", -1)): "animator-fixed-update-managed-wrapper",
        }
        for function in engine_dispatch.get("functions", {}).get("UnityPlayer", []):
            begin = int(function["rva"])
            result[begin].append({"catalog": "animator-engine-dispatch", "role": roles.get(begin, "supporting-function"),
                                  "begin_rva": begin, "end_rva": function.get("declaredEnd")})
    if native_consumers:
        for key, function in native_consumers.get("functions", {}).items():
            begin = int(function["rva"])
            result[begin].append({"catalog": "animator-parameter-native-consumers", "role": key,
                                  "begin_rva": begin,
                                  "end_rva": function.get("declaredEnd", function.get("end"))})
    return result


def run(acceptance_path: Path, manifest_path: Path, frontier_path: Path,
        output: Path, engine_dispatch_path: Path | None = None,
        native_consumers_path: Path | None = None) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance, manifest, frontier = (_load(acceptance_path), _load(manifest_path), _load(frontier_path))
    engine_dispatch = _load(engine_dispatch_path) if engine_dispatch_path else None
    native_consumers = _load(native_consumers_path) if native_consumers_path else None
    fragments, static_calls = _frontier_indices(frontier)
    catalogs = _catalog(engine_dispatch, native_consumers)

    manifest_entries = {row["function_id"]: int(row["entry_rva"]) for row in manifest["functions"]}
    # A callee's captured return address is itself execution evidence for the
    # caller callsite.  Therefore the logical caller need only have a manifest
    # identity; it does not also need a redundant entry observation.
    observed_roots = {rva: _point_id(fid) for fid, rva in manifest_entries.items()
                      if fid.startswith("UnityPlayer.")}

    edge_groups: dict[tuple[str, str], dict[str, Any]] = {}
    external_groups: dict[tuple[str, str], dict[str, Any]] = {}
    caller_rows = []
    unresolved_caller_evidence = []
    invalid_static_joins = []
    for point in acceptance["points"]:
        callee_point = point["point"]
        callee_rva = manifest_entries[point["function_id"]]
        for evidence in point.get("runtime_caller_evidence", []):
            runtime_function = evidence.get("caller_runtime_function")
            if not isinstance(runtime_function, dict):
                unresolved_caller_evidence.append({
                    "callee_point": callee_point,
                    "reason": "caller_runtime_function_absent",
                    "evidence": evidence,
                })
                continue
            begin = int(runtime_function["begin_rva"])
            callsite = int(evidence["callsite_rva"])
            fragment = fragments.get(begin)
            logical_root = fragment["logical_root_rva"] if fragment else None
            caller_point = observed_roots.get(logical_root) if logical_root is not None else None
            static = static_calls.get(callsite)
            static_match = bool(static and logical_root == static["logical_root_rva"] and
                                (static["kind"] == "indirect" or static["target_rva"] == callee_rva))
            if caller_point and not static_match:
                invalid_static_joins.append({"caller_point": caller_point, "callee_point": callee_point,
                                             "callsite_rva": callsite, "static_callsite": static})
            catalog_matches = catalogs.get(begin, [])
            row = {
                "callee_point": callee_point,
                "callee_entry_rva": callee_rva,
                "caller_runtime_function": runtime_function,
                "callsite_rva": callsite,
                "call_kind": evidence["call_kind"],
                "observation_count": int(evidence["observation_count"]),
                "first_qpc": int(evidence["first_qpc"]),
                "last_qpc": int(evidence["last_qpc"]),
                "logical_owner": ({**fragment, "point": caller_point} if fragment else None),
                "static_callsite": static,
                "static_match": static_match,
                "catalog_matches": catalog_matches,
            }
            caller_rows.append(row)
            if caller_point and static_match:
                key = (caller_point, callee_point)
                group = edge_groups.setdefault(key, {"caller_point": caller_point, "callee_point": callee_point,
                    "callsite_rvas": [], "observation_count": 0, "first_qpc": row["first_qpc"],
                    "last_qpc": row["last_qpc"], "call_kinds": set(),
                    "evidence_scope": point.get("evidence_scope", "marked_window")})
                group["callsite_rvas"].append(callsite)
                group["observation_count"] += row["observation_count"]
                group["first_qpc"] = min(group["first_qpc"], row["first_qpc"])
                group["last_qpc"] = max(group["last_qpc"], row["last_qpc"])
                group["call_kinds"].add(row["call_kind"])
            for match in catalog_matches:
                key = (match["catalog"] + ":" + match["role"], callee_point)
                group = external_groups.setdefault(key, {"caller_catalog_identity": match,
                    "callee_point": callee_point, "callsite_rvas": [], "observation_count": 0,
                    "first_qpc": row["first_qpc"], "last_qpc": row["last_qpc"]})
                group["callsite_rvas"].append(callsite)
                group["observation_count"] += row["observation_count"]
                group["first_qpc"] = min(group["first_qpc"], row["first_qpc"])
                group["last_qpc"] = max(group["last_qpc"], row["last_qpc"])

    def finish(group: dict[str, Any]) -> dict[str, Any]:
        out = dict(group)
        out["callsite_rvas"] = sorted(set(out["callsite_rvas"]))
        if isinstance(out.get("call_kinds"), set):
            out["call_kinds"] = sorted(out["call_kinds"])
        out["evidence"] = "runtime return address + unique predecessor call + PDATA owner + audited logical-fragment membership"
        return out

    logical_edges = [finish(edge_groups[key]) for key in sorted(edge_groups)]
    external_edges = [finish(external_groups[key]) for key in sorted(external_groups)]
    source_paths = {"entry-acceptance": acceptance_path, "native-exit-manifest": manifest_path,
                    "native-frontier": frontier_path}
    if engine_dispatch_path:
        source_paths["animator-engine-dispatch"] = engine_dispatch_path
    if native_consumers_path:
        source_paths["animator-native-consumers"] = native_consumers_path
    result = {
        "schema": "uc.entry-runtime-static-join.v1",
        "sources": {key: {"path": str(path), "sha256": file_hash(path)} for key, path in source_paths.items()},
        "session": acceptance.get("session"), "generation": acceptance.get("generation"),
        "accepted_input": bool(acceptance.get("accepted")),
        "logical_runtime_edges": logical_edges,
        "catalog_anchored_runtime_edges": external_edges,
        "caller_evidence": caller_rows,
        "unresolved_caller_evidence": unresolved_caller_evidence,
        "checks": {
            "logical_edge_count": len(logical_edges),
            "catalog_anchored_edge_count": len(external_edges),
            "caller_evidence_count": len(caller_rows),
            "pdata_owned_caller_evidence_count": sum(
                isinstance(row.get("caller_runtime_function"), dict) for row in caller_rows),
            "static_matched_caller_evidence_count": sum(
                row.get("static_match") is True for row in caller_rows),
            "catalog_matched_caller_evidence_count": sum(
                bool(row.get("catalog_matches")) for row in caller_rows),
            "unmatched_caller_evidence_count": sum(
                not row.get("static_match") and not row.get("catalog_matches")
                for row in caller_rows),
            "invalid_static_join_count": len(invalid_static_joins),
            "unresolved_caller_evidence_count": len(unresolved_caller_evidence),
            "all_logical_edges_static_verified": not invalid_static_joins,
        },
        "invalid_static_joins": invalid_static_joins,
        "not_proven": [
            "semantic purpose of an edge beyond the catalog identity",
            "call/return pairing or duration",
            "object, entity, graph or character identity",
            "cross-thread scheduling causality",
            "coverage outside each point's declared evidence scope",
            "complete Animator execution graph or complete controller",
        ],
    }
    output.mkdir(parents=True)
    artifact = output / "entry-runtime-static-join.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.entry-runtime-static-join-report.v1",
              "artifact": {"path": str(artifact), "sha256": file_hash(artifact)},
              **result["checks"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--frontier", type=Path, required=True)
    parser.add_argument("--engine-dispatch", type=Path)
    parser.add_argument("--native-consumers", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.acceptance.resolve(), args.manifest.resolve(), args.frontier.resolve(),
             args.out.resolve(),
             args.engine_dispatch.resolve() if args.engine_dispatch else None,
             args.native_consumers.resolve() if args.native_consumers else None)
