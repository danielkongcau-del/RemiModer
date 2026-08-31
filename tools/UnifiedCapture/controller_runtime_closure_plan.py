"""Build the bounded runtime plan for the remaining controller call chains.

The plan is source-bound but process-independent.  Its invoker predicate is
declared as module+rva and is resolved only after target-process site
qualification by p1_apply_entry_qualification.py.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE


TASK_IDS = {
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
}

ECS_LIFECYCLE_IDS = {
    "ODKPBBAJAEG..ctor@0x101b4b90",
    "ODKPBBAJAEG.Start@0x101b3cf0",
    "ODKPBBAJAEG.Update@0x101b45f0",
    "ODKPBBAJAEG.OnDestroy@0x101b3f80",
    "ODKPBBAJAEG.CreateFilters@0x101b41f0",
}

PARAMETER_IDS = {
    "UnityPlayer.ResetTriggerID.selected-parameters@0xca49d0",
    "UnityPlayer.SetBoolID.selected-parameters@0xca5c50",
    "UnityPlayer.SetFloatID.selected-parameters@0xca6c20",
    "UnityPlayer.SetIntegerID.selected-parameters@0xca7130",
    "UnityPlayer.SetTriggerID.selected-parameters@0xca8150",
}

WRAPPER_ID = "ParallelForJobStruct<IKNHGFBHLLK>.Execute@0x7585e30"
BRIDGE_ID = "GameAssembly.animator-fixed-update-bridge@0x1fc5f030"


def _source(path: Path) -> dict:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _retention(registers: list[str], evidence: list[str], max_keys: int) -> dict:
    return {"mode": "first_per_composite_key", "max_keys": max_keys,
            "key": [
                {"kind": "entry_return_address", "evidence": evidence},
                *({"kind": "register", "register": register, "evidence": evidence}
                  for register in registers),
            ]}


def _register(read_id: str, register: str, evidence: list[str], width: int = 8) -> dict:
    return {"id": read_id, "op": "register", "base": register, "phase": "enter",
            "width": width, "evidence": evidence}


def _native_point(image: NativePE, point_id: str, rva: int, purpose: str,
                  evidence: list[str], reads: list[dict], retention: dict | None = None,
                  runtime_predicates: list[dict] | None = None) -> dict:
    if image.by_start.get(rva) is None:
        raise ValueError(f"{point_id}: not an exact GameAssembly .pdata entry")
    point = {"id": point_id, "backend": "gum_probe", "module": "game", "rva": rva,
             "expected_prefix": image.bytes_at(rva, 32).hex(), "evidence": evidence,
             "capture_purpose": purpose,
             "interpretation": "raw entry ABI at an evidence-qualified native function",
             "reads": reads}
    if retention is not None:
        point["retention"] = retention
    if runtime_predicates:
        point["runtime_predicates"] = runtime_predicates
    return point


def _assert_authorities(task_text: str, shared_text: str, ecs_text: str,
                        api: dict, gap: dict):
    required_task = (
        "METHOD|33853|63|Tick|0x1e469820|",
        "METHOD|33853|67|RunTask|0x1e46b480|",
        "p0=behaviorTree:<none>.BehaviorTree|p1=taskIndex:<none>.Int32|"
        "p2=stackIndex:<none>.Int32|p3=previousStatus:<none>.TaskStatus",
    )
    if any(value not in task_text for value in required_task):
        raise ValueError("BehaviorManager Tick/RunTask authority mismatch")
    if "METHOD|48226|0|Execute|0x7c01b0|" not in shared_text:
        raise ValueError("IKNHGFBHLLK.Execute authority mismatch")
    if "METHOD|48224|45|KBPGJAPPBLI|0x15fe6d20|" not in ecs_text:
        raise ValueError("ODKPBBAJAEG consumer authority mismatch")
    invoke = api.get("invoke", {})
    expected = {"gameTargetRva": 0xacdfe0, "invokerRva": 0x4e30,
                "bridgeCodeRva": 0x1fc5f030, "methodInvokerOffset": 16}
    if any(invoke.get(key) != value for key, value in expected.items()):
        raise ValueError("Animator invoker authority mismatch")
    dispatch = gap.get("parallel_job_dispatch", {})
    if dispatch.get("static_chain_status") != "SOURCE_VERIFIED" or \
            dispatch.get("concrete_execute_thunk", {}).get("rva") != 0x7c01b0 or \
            dispatch.get("shared_body", {}).get("rva") != 0x12df4580 or \
            dispatch.get("shared_body", {}).get("consumer_rva") != 0x15fe6d20:
        raise ValueError("parallel job static chain mismatch")


def run(base_plan_path: Path, task_path: Path, shared_path: Path, ecs_path: Path,
        api_path: Path, static_gap_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    base = json.loads(base_plan_path.read_text(encoding="utf-8-sig"))
    api = json.loads(api_path.read_text(encoding="utf-8-sig"))
    gap = json.loads(static_gap_path.read_text(encoding="utf-8-sig"))
    _assert_authorities(task_path.read_text(encoding="utf-8-sig"),
                        shared_path.read_text(encoding="utf-8-sig"),
                        ecs_path.read_text(encoding="utf-8-sig"), api, gap)
    if base.get("schema") != "uc.capture-plan.v1":
        raise ValueError("base plan schema")
    points_by_id = {point["id"]: point for point in base["points"]}
    selected_ids = TASK_IDS | ECS_LIFECYCLE_IDS | PARAMETER_IDS | {WRAPPER_ID, BRIDGE_ID}
    missing = selected_ids - set(points_by_id)
    if missing:
        raise ValueError(f"base plan lacks selected points: {sorted(missing)}")

    sources = copy.deepcopy(base["sources"])
    sources.update({
        "controller-runtime-closure-tool": _source(Path(__file__)),
        "task-executor-authority": _source(task_path),
        "job-concrete-authority": _source(shared_path),
        "ecs-consumer-authority": _source(ecs_path),
        "animator-invoker-authority": _source(api_path),
        "static-gap-analysis": _source(static_gap_path),
    })
    module_path = Path(sources["game-module"]["path"])
    if file_hash(module_path) != base["modules"]["game"]["sha256"]:
        raise ValueError("GameAssembly source identity mismatch")
    image = NativePE(module_path)

    identity_evidence = ["game-module", "task-executor-authority", "static-gap-analysis"]
    points = []
    for point_id in sorted(selected_ids, key=lambda value: base["points"].index(points_by_id[value])):
        point = copy.deepcopy(points_by_id[point_id])
        if point_id in TASK_IDS:
            point["retention"] = _retention(["rcx"], identity_evidence, 4096)
        elif point_id in ECS_LIFECYCLE_IDS:
            point["retention"] = _retention(["rcx"], identity_evidence, 1024)
        elif point_id == WRAPPER_ID:
            point["retention"] = _retention(["r9"], identity_evidence, 8192)
        elif point_id == BRIDGE_ID:
            point["retention"] = _retention(
                ["rcx"], ["game-module", "animator-invoker-authority"], 4096)
        points.append(point)

    invoker_evidence = ["game-module", "animator-invoker-authority"]
    points.append(_native_point(
        image, "GameAssembly.AnimatorFixedUpdate.invoker@0x4e30", 0x4e30,
        "filtered exact invoker-to-AnimatorFixedUpdate bridge dispatch", invoker_evidence,
        [_register("code-target", "rcx", invoker_evidence),
         _register("method-object", "rdx", invoker_evidence),
         _register("argument-vector", "r9", invoker_evidence),
         {"id": "argument-vector-window", "op": "block", "base": "r9", "offset": 0,
          "phase": "enter", "size": 24, "evidence": invoker_evidence}],
        runtime_predicates=[{"read_id": "code-target", "op": "eq", "module": "game",
                             "rva": 0x1fc5f030, "evidence": invoker_evidence}],
    ))

    task_evidence = ["game-module", "task-executor-authority"]
    points.extend([
        _native_point(
            image, "BehaviorManager.Tick@0x1e469820", 0x1e469820,
            "ODK consumer to behavior-tree scheduling causality", task_evidence,
            [_register("behavior-manager", "rcx", task_evidence),
             _register("behavior-tree", "rdx", task_evidence)],
            _retention(["rdx"], task_evidence, 8192)),
        _native_point(
            image, "BehaviorManager.RunTask@0x1e46b480", 0x1e46b480,
            "behavior-tree scheduler to concrete task callback causality", task_evidence,
            [_register("behavior-manager", "rcx", task_evidence),
             _register("behavior-tree", "rdx", task_evidence),
             _register("task-index", "r8", task_evidence, 4),
             _register("stack-index", "r9", task_evidence, 4),
             {"id": "previous-status", "op": "scalar", "base": "rsp", "offset": 40,
              "phase": "enter", "width": 4, "evidence": task_evidence}],
            _retention(["rdx", "r8"], task_evidence, 32768)),
    ])

    job_evidence = ["game-module", "job-concrete-authority", "ecs-consumer-authority",
                    "static-gap-analysis"]
    points.extend([
        _native_point(
            image, "IKNHGFBHLLK.shared-execute-body@0x12df4580", 0x12df4580,
            "concrete job thunk shared-body branch selection", job_evidence,
            [_register("job-data", "rcx", job_evidence),
             _register("entity-index", "rdx", job_evidence, 4)],
            _retention(["rcx", "rdx"], job_evidence, 8192)),
        _native_point(
            image, "ODKPBBAJAEG.KBPGJAPPBLI@0x15fe6d20", 0x15fe6d20,
            "parallel job consumer to BehaviorManager.Tick causality", job_evidence,
            [_register("entity-index", "rcx", job_evidence, 4)],
            _retention(["rcx"], job_evidence, 8192)),
    ])

    plan = {
        "schema": "uc.capture-plan.v1",
        "plan_id": "controller-runtime-closure-causal-v1",
        "plan_revision": 1,
        "modules": copy.deepcopy(base["modules"]),
        "sources": sources,
        "resources": {"slots_per_point": 512, "max_record_bytes": 4096,
                      "capture_xmm": True},
        "points": points,
        "scope": {
            "claims": ["raw synchronous call-chain evidence", "object-candidate continuity",
                       "process-bound invoker dispatch filtering"],
            "not_claimed": ["ObjectInstance", "EntityIdentity", "cross-thread causality",
                            "complete controller"],
            "automatic_stop": False,
        },
    }
    validation = validate(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_path = output / "capture-plan.runtime-closure.json"
    plan_path.write_bytes(canonical(plan))
    report = {
        "schema": "uc.controller-runtime-closure-plan.v1",
        "output_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "logical_points": len(points),
        "copied_task_points": len(TASK_IDS),
        "copied_ecs_lifecycle_points": len(ECS_LIFECYCLE_IDS),
        "copied_parameter_consumer_points": len(PARAMETER_IDS),
        "new_causal_points": 5,
        "runtime_predicate_points": 1,
        "runtime_predicate_binding_stage": "after-target-site-qualification-before-v2-compilation",
        "validation": validation,
        "expected_runtime_yields": [
            "filtered invoker to 0x1fc5f030 bridge dispatch",
            "ODK consumer to BehaviorManager.Tick to RunTask call chain",
            "task object-candidate continuity across selected lifecycle callbacks",
            "runtime selection or covered-window non-observation of the job branch",
        ],
        "not_established_by_plan_alone": ["Remielle EntityIdentity", "cross-thread Job causality",
                                           "per-move semantic labels", "complete controller"],
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), **report}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-plan", type=Path, required=True)
    parser.add_argument("--task-executors", type=Path, required=True)
    parser.add_argument("--task-shared-values", type=Path, required=True)
    parser.add_argument("--ecs-candidates", type=Path, required=True)
    parser.add_argument("--animator-api", type=Path, required=True)
    parser.add_argument("--static-gap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def invoke():
        try:
            return run(args.base_plan.resolve(), args.task_executors.resolve(),
                       args.task_shared_values.resolve(), args.ecs_candidates.resolve(),
                       args.animator_api.resolve(), args.static_gap.resolve(), args.out.resolve())
        except Exception as error:
            write_failure(args.out, "controller_runtime_closure_plan", error,
                          {key: str(value) for key, value in vars(args).items()})
            raise
    run_main(invoke)
