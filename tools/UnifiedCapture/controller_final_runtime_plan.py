"""Build one narrow source plan for the remaining controller runtime frontier.

The plan deliberately excludes selector, fixed-update invoker and the covered
but unobserved legacy job branch.  It captures only three still-open evidence
groups: native Behavior identity/lifetime, managed-task to native Animator
receiver identity, and two bounded native Animator stages plus selected
parameter consumers for marked-window attribution.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE


TASK_IDS = (
    "SetBoolParameter.OnUpdate@0x1f76e390",
    "SetIntegerParameter.OnUpdate@0x1f8360e0",
    "SetTriggerParameter.OnUpdate@0x14a207b0",
)
CONSUMER_IDS = (
    "UnityPlayer.ResetTriggerID.selected-parameters@0xca49d0",
    "UnityPlayer.SetBoolID.selected-parameters@0xca5c50",
    "UnityPlayer.SetFloatID.selected-parameters@0xca6c20",
    "UnityPlayer.SetIntegerID.selected-parameters@0xca7130",
    "UnityPlayer.SetTriggerID.selected-parameters@0xca8150",
)
STAGES = (
    ("UnityPlayer.AnimatorStage.0xcd4c80", 0xCD4C80),
    ("UnityPlayer.AnimatorStage.0xcd9640", 0xCD9640),
)


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _reg(rid: str, register: str, evidence: list[str], width: int = 8) -> dict[str, Any]:
    return {"id": rid, "base": register, "op": "register", "width": width,
            "phase": "enter", "evidence": evidence}


def _scalar(rid: str, base: str, offset: int, width: int,
            evidence: list[str]) -> dict[str, Any]:
    return {"id": rid, "base": base, "offset": offset, "op": "scalar",
            "width": width, "phase": "enter", "evidence": evidence}


def _block(rid: str, base: str, size: int, evidence: list[str]) -> dict[str, Any]:
    return {"id": rid, "base": base, "op": "block", "size": size,
            "phase": "enter", "evidence": evidence}


def _point(image: NativePE, point_id: str, module: str, rva: int,
           reads: list[dict[str, Any]], evidence: list[str], purpose: str,
           retention: dict[str, Any] | None = None) -> dict[str, Any]:
    owner = image.containing(rva)
    if owner is None or owner.begin != rva:
        raise ValueError(f"point is not an exact PDATA entry: {point_id}")
    row: dict[str, Any] = {
        "id": point_id, "backend": "gum_probe", "module": module, "rva": rva,
        "expected_prefix": image.bytes_at(rva, 32).hex(), "reads": reads,
        "evidence": evidence, "capture_purpose": purpose,
        "interpretation": "raw entry ABI at an evidence-qualified native function",
    }
    if retention is not None:
        row["retention"] = retention
    return row


def _first_per_rcx(evidence: list[str], max_keys: int = 4096) -> dict[str, Any]:
    return {
        "mode": "first_per_composite_key", "max_keys": max_keys,
        "key": [
            {"kind": "entry_return_address", "evidence": evidence},
            {"kind": "register", "register": "rcx", "evidence": evidence},
        ],
    }


def _assert_authority(task_text: str, layout_text: str) -> None:
    signatures = (
        "METHOD|33853|3|TryLoadBehavior|0x1e45dff0|",
        "p0=entityID:<none>.UInt32|p1=behavior:<none>.Behavior|",
        "METHOD|33853|42|LoadBehaviorComplete|0x1e45eef0|",
        "p0=behavior:<none>.Behavior|p1=behaviorTree:<none>.BehaviorTree|",
        "METHOD|33853|50|DestroyBehavior|0x1e467aa0|",
    )
    fields = (
        "private IntPtr m_CachedPtr; // 0x10",
        "private ExternalBehavior _externalBehavior; // 0x60",
        "private BehaviorSource mBehaviorSource; // 0x70",
        "public String behaviorName; // 0x10",
        "private int behaviorID; // 0x20",
        "private IBehavior mOwner; // 0x60",
        "public SharedBool boolValue; // 0x60",
        "public SharedInt intValue; // 0x60",
        "private Animator animator; // 0x70",
        "private OAFMFKKNHJA animatorComponent; // 0x58",
        "private Animator OJHBHGLAPCH; // 0x60",
    )
    missing = [row for row in signatures if row not in task_text]
    missing += [row for row in fields if row not in layout_text]
    if missing:
        raise ValueError(f"authoritative signature/layout changed: {missing}")


def run(base_plan_path: Path, game_module: Path, unity_module: Path,
        task_authority: Path, type_layout: Path, native_consumers: Path,
        animator_dispatch: Path, runtime_stage_join: Path, closure_ledger: Path,
        output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    base = json.loads(base_plan_path.read_text(encoding="utf-8-sig"))
    if base.get("schema") != "uc.capture-plan.v1":
        raise ValueError("base plan must be a v1 source plan")
    _assert_authority(task_authority.read_text(encoding="utf-8-sig"),
                      type_layout.read_text(encoding="utf-8-sig"))
    game = NativePE(game_module)
    unity = NativePE(unity_module)
    if file_hash(game_module) != base["modules"]["game"]["sha256"] or \
            file_hash(unity_module) != base["modules"]["unity"]["sha256"]:
        raise ValueError("module identity differs from the prior qualified source plan")

    source_paths = {
        "game-module": game_module,
        "unity-module": unity_module,
        "task-executor-authority": task_authority,
        "runtime-field-layout": type_layout,
        "native-consumers": native_consumers,
        "animator-dispatch-authority": animator_dispatch,
        "animator-stage-runtime-join": runtime_stage_join,
        "controller-closure-ledger": closure_ledger,
        "final-runtime-plan-tool": Path(__file__),
    }
    sources = {key: _source(path) for key, path in source_paths.items()}
    life_refs = ["game-module", "task-executor-authority", "runtime-field-layout"]
    task_refs = ["game-module", "task-executor-authority", "runtime-field-layout",
                 "controller-closure-ledger"]
    consumer_refs = ["unity-module", "native-consumers", "controller-closure-ledger"]
    stage_refs = ["unity-module", "animator-dispatch-authority",
                  "animator-stage-runtime-join", "controller-closure-ledger"]

    points: list[dict[str, Any]] = []
    points.append(_point(
        game, "BehaviorManager.TryLoadBehavior@0x1e45dff0", "game", 0x1E45DFF0,
        [_reg("manager", "rcx", life_refs), _reg("entity-id", "rdx", life_refs, 4),
         _reg("behavior", "r8", life_refs), _reg("ready-callback", "r9", life_refs)],
        life_refs, "native entity id to Behavior load-request binding"))
    load_reads = [
        _reg("manager", "rcx", life_refs), _reg("behavior", "rdx", life_refs),
        _reg("behavior-tree", "r8", life_refs),
        _scalar("behavior-source", "rdx", 0x70, 8, life_refs),
        _scalar("behavior-name", "behavior-source", 0x10, 8, life_refs),
        _block("behavior-name-object", "behavior-name", 128, life_refs),
        _scalar("behavior-id", "behavior-source", 0x20, 4, life_refs),
        _scalar("behavior-owner", "behavior-source", 0x60, 8, life_refs),
        _scalar("external-behavior", "rdx", 0x60, 8, life_refs),
        _scalar("external-source", "external-behavior", 0x18, 8, life_refs),
        _scalar("external-name", "external-source", 0x10, 8, life_refs),
        _block("external-name-object", "external-name", 128, life_refs),
    ]
    points.append(_point(
        game, "BehaviorManager.LoadBehaviorComplete@0x1e45eef0", "game", 0x1E45EEF0,
        load_reads, life_refs, "Behavior to internal tree and authoritative behavior-name binding"))
    points.append(_point(
        game, "BehaviorManager.DestroyBehavior@0x1e467aa0", "game", 0x1E467AA0,
        [_reg("manager", "rcx", life_refs), _reg("behavior", "rdx", life_refs),
         _reg("execution-status", "r8", life_refs, 4)],
        life_refs, "native Behavior lifetime end boundary"))

    base_points = {point["id"]: point for point in base["points"]}
    missing = set(TASK_IDS + CONSUMER_IDS) - set(base_points)
    if missing:
        raise ValueError(f"base source plan lacks required points: {sorted(missing)}")
    for point_id in TASK_IDS:
        point = copy.deepcopy(base_points[point_id])
        point["evidence"] = task_refs
        point["capture_purpose"] = "managed task instance to native Unity Animator receiver identity"
        point["retention"] = _first_per_rcx(task_refs)
        if point_id.startswith("SetBool") or point_id.startswith("SetInteger"):
            point["reads"].append(_scalar("animator-native-receiver", "animator-object", 0x10, 8, task_refs))
        else:
            point["reads"].extend([
                _scalar("nested-unity-animator", "animator-component", 0x60, 8, task_refs),
                _scalar("animator-native-receiver", "nested-unity-animator", 0x10, 8, task_refs),
            ])
        for read in point["reads"]:
            read["evidence"] = task_refs
        points.append(point)

    for point_id in CONSUMER_IDS:
        point = copy.deepcopy(base_points[point_id])
        point["evidence"] = consumer_refs
        point["capture_purpose"] = "selected native Animator parameter consumer in marked action windows"
        point.pop("retention", None)
        for read in point["reads"]:
            read["evidence"] = consumer_refs
        points.append(point)

    for point_id, rva in STAGES:
        points.append(_point(
            unity, point_id, "unity", rva,
            [_reg("stage-object", "rcx", stage_refs), _reg("raw-rdx", "rdx", stage_refs),
             _reg("raw-r8", "r8", stage_refs), _reg("raw-r9", "r9", stage_refs)],
            stage_refs, "bounded native Animator stage stream for same-session receiver joins"))

    plan = {
        "schema": "uc.capture-plan.v1",
        "plan_id": "controller-final-runtime-frontier-v1",
        "plan_revision": 1,
        "modules": copy.deepcopy(base["modules"]),
        "sources": sources,
        "resources": {"slots_per_point": 4096, "max_record_bytes": 4096,
                      "capture_xmm": False},
        "points": points,
        "scope": {
            "automatic_stop": False, "fixed_duration": False, "snapshot_limit": False,
            "included_claims": [
                "entity-id to Behavior load request",
                "Behavior load-complete and destruction boundaries",
                "managed Animator m_CachedPtr to selected native receiver",
                "marked-window native Animator stage and selected parameter streams",
            ],
            "excluded_as_already_closed": ["random selector outcomes", "selected API invoker edge"],
            "excluded_after_covered_nonobservation": ["legacy IKNHGFBHLLK job branch"],
            "environment_contingent": ["ordinary special independent coverage"],
            "not_claimed_by_plan_alone": ["EntityIdentity promotion", "per-move semantic attribution",
                                           "complete controller"],
        },
    }
    validation = validate(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_path = output / "capture-plan.controller-final-runtime.json"
    plan_path.write_bytes(canonical(plan))
    report = {
        "schema": "uc.controller-final-runtime-plan-report.v1",
        "plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "points": len(points), "lifecycle_points": 3, "task_identity_points": 3,
        "selected_parameter_consumers": 5, "animator_stage_points": 2,
        "full_stream_points": 7, "first_per_task_instance_points": 3,
        "expected_gameplay_sessions": 1,
        "ordinary_special_may_require_later_reachable_environment": True,
        "validation": validation,
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-plan", type=Path, required=True)
    parser.add_argument("--game-module", type=Path, required=True)
    parser.add_argument("--unity-module", type=Path, required=True)
    parser.add_argument("--task-authority", type=Path, required=True)
    parser.add_argument("--type-layout", type=Path, required=True)
    parser.add_argument("--native-consumers", type=Path, required=True)
    parser.add_argument("--animator-dispatch", type=Path, required=True)
    parser.add_argument("--runtime-stage-join", type=Path, required=True)
    parser.add_argument("--closure-ledger", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    def invoke():
        try:
            return run(*(getattr(args, name).resolve() for name in (
                "base_plan", "game_module", "unity_module", "task_authority", "type_layout",
                "native_consumers", "animator_dispatch", "runtime_stage_join",
                "closure_ledger", "out")))
        except Exception as error:
            write_failure(args.out, "controller_final_runtime_plan", error,
                          {key: str(value) for key, value in vars(args).items()})
            raise

    run_main(invoke)
