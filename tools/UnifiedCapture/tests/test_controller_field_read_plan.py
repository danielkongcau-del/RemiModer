from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
sys.path.insert(0, str(ROOT))

from controller_field_read_plan import run
from p1_apply_entry_qualification import run as apply_entry_qualification
from uc.model import validate


def test_field_enrichment_is_source_verified_and_bounded(tmp_path):
    report = run(
        WORKSPACE / "extracted/analysis/controller-causal-frontier-retained-20260830-v1/capture-plan.caller-retained.json",
        WORKSPACE / "extracted/dump-x-xa.cs",
        WORKSPACE / "extracted/behavior-task-executors-20260827-v2.txt",
        WORKSPACE / "extracted/behavior-ecs-candidates-20260827.txt",
        WORKSPACE / "extracted/odk-job-reflection-type-20260827-v2.txt",
        tmp_path / "derived",
    )
    assert report["logical_points"] == 41
    assert (report["enriched_points"], report["task_points"], report["ecs_points"],
            report["job_points"]) == (16, 10, 5, 1)
    assert report["maximum_point_record_bytes"] <= report["declared_max_record_bytes"]
    assert report["job_instruction_contract"]["all_declared_bytes_decoded"]

    plan = json.loads((tmp_path / "derived/capture-plan.field-enriched.json").read_text("utf-8"))
    validate(plan, verify_sources=True)
    points = {point["id"]: point for point in plan["points"]}
    task = points["SetBoolParameter.OnUpdate@0x1f76e390"]
    assert task["field_read_contract"]["semantic_upgrade"] is False
    assert {read["id"] for read in task["reads"]} >= {
        "raw-rcx", "shared-bool-object", "parameter-hash", "set-once"
    }
    update = points["ODKPBBAJAEG.Update@0x101b45f0"]
    assert {read["id"] for read in update["reads"]} >= {
        "ecs-filter-object", "filter-system", "filter-entity-count", "job-handle-storage"
    }
    start = points["ODKPBBAJAEG.Start@0x101b3cf0"]
    assert "filter-system" not in {read["id"] for read in start["reads"]}
    job = points["ParallelForJobStruct<IKNHGFBHLLK>.Execute@0x7585e30"]
    assert {read["id"] for read in job["reads"]} >= {
        "raw-rcx", "raw-rdx", "raw-r8", "raw-r9", "raw-stack-argument-5",
        "raw-job-ranges-window",
    }

    # Replay a previously sealed 41-site qualification only as an offline
    # compiler fixture.  This proves the v1 -> process-bound v2 transform keeps
    # the field authorities; it does not claim that the old PID is live.
    qualified_out = tmp_path / "qualified"
    apply_entry_qualification(
        WORKSPACE / "extracted/analysis/controller-causal-frontier-p1-source-bound-20260830-v2/native-exit-manifest.source-bound.json",
        tmp_path / "derived/capture-plan.field-enriched.json",
        WORKSPACE / "extracted/analysis/controller-causal-frontier-runtime-20260830-p59680-v2/site-qualification-evidence.json",
        qualified_out,
    )
    qualified = json.loads((qualified_out / "entry-plan.target-qualified.json").read_text("utf-8"))
    assert "runtime-field-layout" in qualified["sources"]
    qualified_task = next(row for row in qualified["observations"]
                          if row["id"] == "SetBoolParameter.OnUpdate@0x1f76e390/entry")
    hash_read = next(row for row in qualified_task["entry"]["reads"]
                     if row["id"] == "parameter-hash")
    assert hash_read["evidence"] == [
        "runtime-field-layout", "task-method-reflection", "game-module", "target-qualification"
    ]
    assert qualified_task["field_read_contract"]["semantic_upgrade"] is False


def test_output_is_immutable(tmp_path):
    output = tmp_path / "derived"
    args = (
        WORKSPACE / "extracted/analysis/controller-causal-frontier-retained-20260830-v1/capture-plan.caller-retained.json",
        WORKSPACE / "extracted/dump-x-xa.cs",
        WORKSPACE / "extracted/behavior-task-executors-20260827-v2.txt",
        WORKSPACE / "extracted/behavior-ecs-candidates-20260827.txt",
        WORKSPACE / "extracted/odk-job-reflection-type-20260827-v2.txt",
        output,
    )
    run(*args)
    try:
        run(*args)
    except FileExistsError:
        pass
    else:
        raise AssertionError("derived evidence output must be immutable")
