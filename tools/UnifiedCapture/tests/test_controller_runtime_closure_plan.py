from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
sys.path.insert(0, str(ROOT))

from controller_runtime_closure_plan import run
from p1_apply_entry_qualification import bind_runtime_predicates
from uc.model import validate


def _inputs(output: Path):
    return (
        WORKSPACE / "extracted/analysis/controller-field-read-plan-20260830-v1/capture-plan.field-enriched.json",
        WORKSPACE / "extracted/behavior-task-executors-20260827-v2.txt",
        WORKSPACE / "extracted/behavior-task-shared-values-20260827.txt",
        WORKSPACE / "extracted/behavior-ecs-candidates-20260827.txt",
        WORKSPACE / "extracted/analysis/behavior-observer/animator-api-usage-20260828-v3-verified/animator-api-usage.json",
        WORKSPACE / "extracted/analysis/controller-static-gap-analysis-20260830-v1/controller-static-gap-analysis.json",
        output,
    )


def test_plan_is_source_verified_bounded_and_process_bindable(tmp_path):
    report = run(*_inputs(tmp_path / "plan"))
    assert report["logical_points"] == 27
    assert report["runtime_predicate_points"] == 1
    plan = json.loads((tmp_path / "plan/capture-plan.runtime-closure.json").read_text("utf-8"))
    validate(plan, verify_sources=True)
    points = {point["id"]: point for point in plan["points"]}
    invoker = points["GameAssembly.AnimatorFixedUpdate.invoker@0x4e30"]
    assert invoker["runtime_predicates"] == [{
        "read_id": "code-target", "op": "eq", "module": "game", "rva": 0x1fc5f030,
        "evidence": ["game-module", "animator-invoker-authority"],
    }]
    assert "when" not in invoker["reads"][0]
    assert points["BehaviorManager.RunTask@0x1e46b480"]["retention"]["key"][2]["register"] == "r8"
    assert points["SetBoolParameter.OnUpdate@0x1f76e390"]["retention"]["key"][1]["register"] == "rcx"

    bound, rows = bind_runtime_predicates(plan, {"sites": [
        {"module": "game", "module_base": 0x180000000},
        {"module": "unity", "module_base": 0x7ff800000000},
    ]})
    bound_invoker = next(point for point in bound["points"] if point["id"] == invoker["id"])
    assert bound_invoker["reads"][0]["when"]["value"] == 0x19fc5f030
    assert rows[0]["resolved_value"] == 0x19fc5f030


def test_output_is_immutable(tmp_path):
    output = tmp_path / "plan"
    run(*_inputs(output))
    try:
        run(*_inputs(output))
    except FileExistsError:
        pass
    else:
        raise AssertionError("runtime closure plan output must be immutable")
