"""Classify controller entry coverage by source-declared native role.

The runtime plan intentionally probes both members of several obfuscated action
method pairs.  Treating every non-observed member as a missing gameplay action
is incorrect when the native inventory already identifies one member as a
wrapper and the other as a native implementation.  This tool keeps those
claims separate and emits a conservative, source-linked capture frontier.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _point(type_name: str, method: str) -> str:
    return f"{type_name}.{method}/entry"


def _status(point: str, observed: set[str], not_observed: set[str]) -> str:
    if point in observed:
        return "OBSERVED_IN_LOSSLESS_COVERED_WINDOW"
    if point in not_observed:
        return "NOT_OBSERVED_IN_COVERED_WINDOW"
    return "NOT_CONFIGURED_OR_COVERAGE_UNKNOWN"


def run(controller_path: Path, inventory_path: Path, caller_join_path: Path,
        output: Path, dispatch_role_paths: list[Path] | None = None) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    controller = _load(controller_path)
    inventory = _load(inventory_path)
    caller_join = _load(caller_join_path)
    dispatch_role_paths = dispatch_role_paths or []
    derived_dispatch = {}
    for path in dispatch_role_paths:
        evidence = _load(path)
        if not all(evidence.get("checks", {}).values()):
            raise ValueError(f"dispatch role evidence failed checks: {path}")
        derived_dispatch[evidence["target_type"]] = evidence
    if not controller.get("lossless") or controller.get("manifest_errors"):
        raise ValueError("controller runtime source is not lossless")

    observed = set(controller.get("observed_points", []))
    not_observed = set(controller.get("not_observed_in_covered_lossless_overall_window", []))
    wanted = {
        "ApplyLogicMoveAction", "HandleAnimatorZoneTagsAction",
        "ModifyEnterBattleStateAction", "SetAbilitySpecialAction",
        "SetTargetAbilitySpecialAction", "TriggerAbilityAction",
    }
    ledger = {row["serializedType"]: row for row in inventory.get("nativeTypeLedger", [])
              if row.get("serializedType") in wanted}
    missing = sorted(wanted - set(ledger))
    if missing:
        raise ValueError(f"inventory misses required types: {missing}")

    ability_rows: list[dict[str, Any]] = []
    wrapper_observed = wrapper_total = native_observed = native_total = 0
    unclassified: list[dict[str, Any]] = []
    runtime_candidates: list[dict[str, Any]] = []
    for type_name in sorted(wanted):
        item = ledger[type_name]
        native = item.get("nativeIdentityAndDispatch", {})
        dispatch = native.get("dispatch")
        base = {
            "serialized_type": type_name,
            "occurrences_in_remielle_assets": int(item.get("occurrences", 0)),
            "occurrences_across_all_51_abilities": native.get("occurrencesAcrossAll51Abilities"),
            "positions": item.get("positions", []),
            "identity_evidence_kind": item.get("identityEvidenceKind"),
            "identity_evidence_source": item.get("identityEvidenceSource"),
        }
        if (not isinstance(dispatch, dict) or not dispatch.get("wrapper") or
                not dispatch.get("nativeImplementation")) and type_name in derived_dispatch:
            evidence = derived_dispatch[type_name]
            methods = {row.get("name"): row for row in native.get("methods", [])}
            assignments = {row["derived_role"]: methods[row["method"]]
                           for row in evidence["classifications"]}
            dispatch = {"wrapper": assignments["wrapper"],
                        "nativeImplementation": assignments["nativeImplementation"]}
            base["dispatch_role_derivation"] = {
                "kind": "complete-pdata-mnemonic-size-shape-equality-to-source-labelled-references",
                "source": _source(next(path for path in dispatch_role_paths
                                       if _load(path)["target_type"] == type_name))}
        if not isinstance(dispatch, dict) or not dispatch.get("wrapper") or not dispatch.get("nativeImplementation"):
            methods = {row.get("name"): row for row in native.get("methods", [])}
            members = []
            for name in ("HCBMKBDIHJB", "BHCIJGGHECM"):
                method = methods.get(name)
                if method:
                    point = _point(type_name, name)
                    members.append({"method": name, "point": point, "rva": method.get("rva"),
                                    "rva_hex": method.get("rvaHex"),
                                    "status": _status(point, observed, not_observed)})
            row = {**base, "dispatch_role_status": "UNCLASSIFIED_BY_NATIVE_INVENTORY",
                   "members": members,
                   "capture_policy": "do not infer wrapper/native role from naming symmetry"}
            ability_rows.append(row)
            unclassified.append(row)
            continue

        roles: dict[str, Any] = {}
        for role, method in (("wrapper", dispatch["wrapper"]),
                             ("native_implementation", dispatch["nativeImplementation"])):
            point = _point(type_name, method["name"])
            state = _status(point, observed, not_observed)
            roles[role] = {"method": method["name"], "point": point,
                           "rva": method["rva"], "rva_hex": method.get("rvaHex"),
                           "status": state,
                           "direct_call_count": method.get("directCallCount")}
            if role == "wrapper":
                wrapper_total += 1
                wrapper_observed += state.startswith("OBSERVED")
            else:
                native_total += 1
                native_observed += state.startswith("OBSERVED")
        row = {**base, "dispatch_role_status": (
            "MECHANICALLY_DERIVED_FROM_SOURCE_CLASSIFIED_CODE_SHAPE"
            if "dispatch_role_derivation" in base else "SOURCE_CLASSIFIED"), "roles": roles}
        if roles["wrapper"]["status"] == "NOT_OBSERVED_IN_COVERED_WINDOW":
            candidate = {"point": roles["wrapper"]["point"], "serialized_type": type_name,
                         "reason": "serialized action wrapper has asset occurrences but was not observed"}
            runtime_candidates.append(candidate)
            row["capture_policy"] = "candidate only if a source-identified asset scenario can execute it"
        else:
            row["capture_policy"] = "wrapper execution is closed for the covered window"
        roles["native_implementation"]["capture_policy"] = (
            "do not schedule gameplay repetition solely to force this alternate implementation path")
        ability_rows.append(row)

    task_points = sorted(point for point in observed | not_observed
                         if point.startswith(("SetBoolParameter.", "SetIntegerParameter.",
                                              "SetTriggerParameter.")))
    task_rows = []
    for point in task_points:
        callback = point.split(".", 1)[1].split("@", 1)[0].split("/", 1)[0]
        role = {"OnStart": "task_start", "OnUpdate": "task_update",
                "OnReset": "task_reset"}.get(callback, "task_other")
        task_rows.append({"point": point, "callback": callback, "role": role,
                          "status": _status(point, observed, not_observed)})

    ecs_points = sorted(point for point in observed | not_observed
                        if point.startswith(("ODKPBBAJAEG.", "ParallelForJobStruct<IKNHGFBHLLK>.")))
    ecs_rows = []
    for point in ecs_points:
        method = point.split(".", 1)[1].split("@", 1)[0].split("/", 1)[0]
        if method in (".ctor", "Start", "CreateFilters", "OnDestroy"):
            role = "ecs_lifecycle"
        elif method in ("Update", "FixedUpdate", "Execute"):
            role = "ecs_schedule_or_update"
        else:
            role = "obfuscated_ecs_method"
        ecs_rows.append({"point": point, "method": method, "role": role,
                         "status": _status(point, observed, not_observed)})

    result = {
        "schema": "uc.controller-role-aware-gap.v1",
        "sources": {"controller_runtime": _source(controller_path),
                    "native_inventory": _source(inventory_path),
                    "caller_join": _source(caller_join_path),
                    "dispatch_role_derivations": [_source(path) for path in dispatch_role_paths]},
        "ability_action_entries": ability_rows,
        "task_callback_entries": task_rows,
        "ecs_entries": ecs_rows,
        "caller_identity_coverage": caller_join.get("summary", {}),
        "summary": {
            "role_classified_action_types": wrapper_total,
            "source_classified_action_types": wrapper_total - len(derived_dispatch),
            "mechanically_derived_action_types": len(derived_dispatch),
            "wrapper_observed": wrapper_observed,
            "wrapper_total": wrapper_total,
            "native_implementation_observed": native_observed,
            "native_implementation_total": native_total,
            "unclassified_action_types": len(unclassified),
            "gameplay_runtime_candidate_count": len(runtime_candidates),
        },
        "gameplay_runtime_candidates": runtime_candidates,
        "bounded_conclusions": [
            f"{wrapper_observed} of {wrapper_total} role-classified action wrappers executed in the covered lossless window",
            "non-observation of a nativeImplementation member is not evidence that its serialized gameplay action did not execute",
            "task OnStart and OnUpdate observations establish native BehaviorManager callback dispatch for the observed task types",
        ],
        "not_proven": [
            "wrapper-to-nativeImplementation fallback semantics",
            "semantic role of the ApplyLogicMoveAction HCB/BHCI pair",
            "that every serialized occurrence executed",
            "per-move attribution, object identity, or complete controller",
        ],
    }
    output.mkdir(parents=True)
    artifact = output / "controller-role-aware-gap.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-role-aware-gap-report.v1",
              "artifact": _source(artifact), **result["summary"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--caller-join", type=Path, required=True)
    parser.add_argument("--dispatch-role", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.controller.resolve(), args.inventory.resolve(), args.caller_join.resolve(), args.out.resolve(),
        [path.resolve() for path in args.dispatch_role])
