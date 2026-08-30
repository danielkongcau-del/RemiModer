"""Build one source-bound controller capture frontier from authoritative evidence.

The output is a v1 entry plan suitable for the existing mechanical manifest,
Ghidra, and target-site qualification pipeline.  It deliberately excludes
alternate nativeImplementation members and chapter-only AirCombat actions.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE


TASK_AND_LIFECYCLE_IDS = (
    "SetBoolParameter.OnStart@0x1f76e200",
    "SetBoolParameter.OnUpdate@0x1f76e390",
    "SetBoolParameter.OnReset@0x1f76e830",
    "SetIntegerParameter.OnStart@0x1f835f50",
    "SetIntegerParameter.OnUpdate@0x1f8360e0",
    "SetIntegerParameter.OnReset@0x1f836580",
    "SetTriggerParameter.OnUpdate@0x14a207b0",
    "SetTriggerParameter.OnReset@0x14a20ac0",
    "SetBoolParameter.OnUpdate@0x14a1f2a0",
    "SetBoolParameter.OnReset@0x14a1f830",
    "ODKPBBAJAEG..ctor@0x101b4b90",
    "ODKPBBAJAEG.Start@0x101b3cf0",
    "ODKPBBAJAEG.Update@0x101b45f0",
    "ODKPBBAJAEG.OnDestroy@0x101b3f80",
    "ODKPBBAJAEG.CreateFilters@0x101b41f0",
    "ParallelForJobStruct<IKNHGFBHLLK>.Execute@0x7585e30",
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path), "sha256": file_hash(path)}


def parameter_subscriptions(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_type = {"float": "SetFloatID", "int": "SetIntegerID", "type4": "SetBoolID",
               "bool/trigger": "SetTriggerID"}
    rows = []
    for item in parameters:
        method = by_type.get(item["typeStr"])
        if method is None:
            raise ValueError(f"unsupported selected parameter type: {item['typeStr']}")
        rows.append({"method": method, "name": item["name"], "id": int(item["id"]),
                     "type": item["typeStr"]})
        if item["typeStr"] == "bool/trigger":
            rows.append({"method": "ResetTriggerID", "name": item["name"], "id": int(item["id"]),
                         "type": item["typeStr"]})
    return sorted(rows, key=lambda row: (row["method"], row["id"], row["name"]))


def selected_wrappers(role_gap: dict[str, Any]) -> list[str]:
    result = []
    for row in role_gap["ability_action_entries"]:
        if row["serialized_type"] == "ModifyEnterBattleStateAction":
            continue
        roles = row.get("roles", {})
        wrapper = roles.get("wrapper")
        if wrapper and wrapper.get("status", "").startswith("OBSERVED"):
            result.append(wrapper["point"].removesuffix("/entry"))
    return sorted(result)


def _copy_point(point: dict[str, Any], evidence: list[str], purpose: str) -> dict[str, Any]:
    row = {key: copy.deepcopy(value) for key, value in point.items()
           if key not in ("reads", "retention", "evidence", "interpretation")}
    row["evidence"] = evidence
    row["interpretation"] = "instruction-event at an evidence-qualified native entry"
    row["capture_purpose"] = purpose
    row["reads"] = [{"id": "raw-rcx", "base": "rcx", "op": "register", "width": 8,
                     "phase": "enter", "evidence": evidence}]
    return row


def _native_point(pe: NativePE, module: str, point_id: str, rva: int,
                  evidence: list[str], purpose: str, reads: list[dict[str, Any]]) -> dict[str, Any]:
    if rva not in pe.by_start:
        raise ValueError(f"{point_id}: not an exact .pdata entry at {rva:#x}")
    return {"id": point_id, "backend": "gum_probe", "module": module, "rva": rva,
            "expected_prefix": pe.bytes_at(rva, 32).hex(), "evidence": evidence,
            "interpretation": "instruction-event at an exact source-verified .pdata entry",
            "capture_purpose": purpose, "reads": reads}


def run(closure_path: Path, controller_plan_path: Path, animator_plan_path: Path,
        role_gap_path: Path, api_path: Path, consumers_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    closure, controller, animator = map(_load, (closure_path, controller_plan_path, animator_plan_path))
    role_gap, api, consumers = map(_load, (role_gap_path, api_path, consumers_path))
    if closure.get("complete_controller") or closure.get("runtime_required_now"):
        raise ValueError("closure ledger is not at the expected offline-frontier state")
    if not api.get("scope", {}).get("selectedBridgeInvocationAbiClosed"):
        raise ValueError("selected bridge ABI is not statically closed")
    if consumers.get("limits", {}).get("liveConsumerProven"):
        raise ValueError("consumer source unexpectedly claims live proof")

    game_source = next(Path(row["path"]) for row in controller["sources"].values()
                       if Path(row["path"]).name.lower() == "gameassembly.dll")
    unity_source = next(Path(row["path"]) for row in animator["sources"].values()
                        if Path(row["path"]).name.lower() == "unityplayer.dll")
    game, unity = NativePE(game_source), NativePE(unity_source)
    modules = {"game": {"image": game_source.name, "sha256": file_hash(game_source)},
               "unity": {"image": unity_source.name, "sha256": file_hash(unity_source)}}
    sources = {"game-module": _source(game_source), "unity-module": _source(unity_source),
               "closure-ledger": _source(closure_path), "controller-plan": _source(controller_plan_path),
               "animator-plan": _source(animator_plan_path), "role-gap": _source(role_gap_path),
               "api-usage": _source(api_path), "native-consumers": _source(consumers_path)}

    controller_points = {row["id"]: row for row in controller["points"]}
    animator_points = {row["id"]: row for row in animator["points"]}
    points = []
    for point_id in TASK_AND_LIFECYCLE_IDS:
        points.append(_copy_point(controller_points[point_id], ["game-module", "controller-plan", "closure-ledger"],
                                  "task reset/lifecycle and object-candidate continuity"))
    for point in animator_points.values():
        points.append(_copy_point(point, ["unity-module", "animator-plan", "closure-ledger"],
                                  "same-window Animator native stage ordering"))
    for point_id in selected_wrappers(role_gap):
        points.append(_copy_point(controller_points[point_id], ["game-module", "controller-plan", "role-gap"],
                                  "marked-move attribution of already proven gameplay wrappers"))

    bridge_reads = [{"id": register, "base": register, "op": "register", "width": 8,
                     "phase": "enter", "evidence": ["game-module", "api-usage"]}
                    for register in ("rcx", "rdx", "r8")]
    for name, rva in (("selected-api-target", int(api["invoke"]["gameTargetRva"])),
                      ("animator-fixed-update-bridge", int(api["invoke"]["bridgeCodeRva"]))):
        points.append(_native_point(game, "game", f"GameAssembly.{name}@0x{rva:x}", rva,
                                    ["game-module", "api-usage"],
                                    "live current-process bridge traversal", copy.deepcopy(bridge_reads)))

    paths = {row["method"]: row for row in consumers["paths"]}
    subscriptions = parameter_subscriptions(consumers["parametersForNextCapture"])
    grouped = {method: [row for row in subscriptions if row["method"] == method]
               for method in sorted({row["method"] for row in subscriptions})}
    for method, selected in grouped.items():
        path = paths[method]
        rva = int(path["fanoutRva"])
        evidence = ["unity-module", "native-consumers"]
        ids = sorted({row["id"] for row in selected})
        reads = [
            {"id": "parameter-id", "base": "rdx", "op": "register", "width": 4,
             "phase": "enter", "when": {"op": "in", "values": ids}, "evidence": evidence},
            {"id": "receiver", "base": "rcx", "op": "register", "width": 8,
             "phase": "enter", "evidence": evidence},
            {"id": "value-gpr", "base": "r8", "op": "register", "width": 8,
             "phase": "enter", "evidence": evidence},
        ]
        point_id = f"UnityPlayer.{method}.selected-parameters@0x{rva:x}"
        points.append(_native_point(unity, "unity", point_id, rva, evidence,
                                    "selected Animator parameter consumer with register predicate", reads))

    ids = [row["id"] for row in points]
    if len(ids) != len(set(ids)):
        raise ValueError("frontier contains duplicate logical point ids")
    plan = {"schema": "uc.capture-plan.v1", "plan_id": "controller-causal-frontier-v8",
            "plan_revision": 1, "modules": modules, "sources": sources,
            "resources": {"slots_per_point": 512, "max_record_bytes": 4096, "capture_xmm": True},
            "points": points}
    validate(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_path = output / "controller-causal-frontier-v8.json"
    plan_path.write_bytes(canonical(plan))
    result = {"schema": "uc.controller-capture-frontier.v1", "activation_ready": False,
              "runtime_required_now": False, "plan": _source(plan_path),
              "logical_points": len(points), "physical_sites": len({(row["module"], row["rva"]) for row in points}),
              "task_lifecycle_points": len(TASK_AND_LIFECYCLE_IDS),
              "animator_stage_points": len(animator_points),
              "ability_wrapper_points": len(selected_wrappers(role_gap)),
              "bridge_points": 2,
              "parameter_subscriptions": len(subscriptions),
              "parameter_physical_points": len(grouped),
              "excluded": ["nativeImplementation alternate members",
                           "ModifyEnterBattleStateAction normal-trial repetition",
                           "unresolved caller names without new observation semantics"],
              "remaining_before_runtime": ["mechanical exit/callsite manifests",
                                           "Ghidra/Capstone range agreement",
                                           "target-process physical-site qualification"]}
    (output / "frontier.json").write_bytes(canonical(result))
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--controller-plan", type=Path, required=True)
    parser.add_argument("--animator-plan", type=Path, required=True)
    parser.add_argument("--role-gap", type=Path, required=True)
    parser.add_argument("--api", type=Path, required=True)
    parser.add_argument("--consumers", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.closure.resolve(), args.controller_plan.resolve(), args.animator_plan.resolve(),
        args.role_gap.resolve(), args.api.resolve(), args.consumers.resolve(), args.out.resolve())
