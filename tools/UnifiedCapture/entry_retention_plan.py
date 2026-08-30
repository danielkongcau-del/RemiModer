"""Derive a caller-retained v1 plan from independently accounted runtime loss."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash, validate


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def derive(source_path: Path, summary_path: Path, output: Path,
           max_keys: int = 65536) -> dict[str, Any]:
    source_path, summary_path, output = (path.resolve() for path in
                                         (source_path, summary_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    if max_keys <= 0 or max_keys & (max_keys - 1):
        raise ValueError("max_keys must be a nonzero power of two")
    source, summary = load(source_path), load(summary_path)
    validate(source, verify_sources=True)
    if summary.get("schema") != "uc.streaming-entry-summary.v1":
        raise ValueError("unsupported runtime summary schema")
    summary_points = {row["point"].removesuffix("/entry"): row
                      for row in summary["points"]}
    point_ids = {row["id"] for row in source["points"]}
    if not set(summary_points) <= point_ids:
        raise ValueError("runtime summary contains points outside source plan")
    plan = copy.deepcopy(source)
    plan["plan_id"] = source["plan_id"] + "-caller-retained"
    plan["plan_revision"] = int(source["plan_revision"]) + 1
    evidence_id = "runtime-loss-summary"
    plan["sources"][evidence_id] = {"path": str(summary_path), "sha256": file_hash(summary_path)}
    promoted, blocked = [], []
    for point in plan["points"]:
        runtime = summary_points.get(point["id"])
        if runtime is None or int(runtime.get("lost_events", 0)) <= 0:
            continue
        if any("when" in read for read in point.get("reads", [])):
            blocked.append({"point": point["id"], "reason": "predicated-read-retention-incompatible",
                            "lost_events": runtime["lost_events"]})
            continue
        point["retention"] = {"mode": "first_per_entry_return_address", "max_keys": max_keys}
        point["evidence"] = list(dict.fromkeys([*point.get("evidence", []), evidence_id]))
        promoted.append({"point": point["id"], "lost_events": runtime["lost_events"],
                         "stored_window_events": runtime["window_events"]})
    if blocked:
        raise ValueError(f"lossy points cannot be promoted safely: {blocked}")
    if not promoted:
        raise ValueError("runtime summary has no promotable lossy points")
    validate(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_path = output / "capture-plan.caller-retained.json"
    plan_path.write_bytes(canonical(plan))
    report = {"schema": "uc.entry-retention-derivation.v1",
        "source_plan": {"path": str(source_path), "sha256": file_hash(source_path)},
        "runtime_summary": {"path": str(summary_path), "sha256": file_hash(summary_path)},
        "plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "points": len(plan["points"]), "retained_points": promoted, "max_keys": max_keys,
        "semantics": "first full raw sample per observed entry return address plus independent callback counts"}
    report_path = output / "report.json"
    report_path.write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "points": len(plan["points"]),
                      "retained_points": len(promoted), "plan_sha256": file_hash(plan_path)},
                     ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-keys", type=int, default=65536)
    args = parser.parse_args()
    run_main(derive, args.plan, args.summary, args.out, args.max_keys)
