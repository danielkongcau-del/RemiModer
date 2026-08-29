"""Mechanically merge compatible v1 entry-probe plans into one activation unit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate


def run(plan_paths: list[Path], plan_id: str, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    if not plan_paths or not plan_id:
        raise ValueError("source plans and plan id are required")
    modules, sources, points, point_ids = {}, {}, [], set()
    slots = max_bytes = 0
    source_rows = []
    for path in plan_paths:
        path = path.resolve()
        plan = json.loads(path.read_text(encoding="utf-8-sig"))
        # Old aggregate plans may retain unused source-table rows after their
        # legacy implementations were deliberately retired.  Validate the
        # plan shape first, then verify only the evidence aliases actually
        # referenced by the merged points below.
        validate(plan, verify_sources=False)
        source_rows.append({"plan_id": plan["plan_id"], "plan_revision": plan["plan_revision"],
                            "path": str(path), "sha256": file_hash(path)})
        for alias, value in plan["modules"].items():
            if alias in modules and modules[alias] != value:
                raise ValueError(f"conflicting module identity: {alias}")
            modules[alias] = value
        for alias, value in plan["sources"].items():
            if alias in sources and sources[alias] != value:
                raise ValueError(f"conflicting source identity: {alias}")
            sources[alias] = value
        for point in plan["points"]:
            if point.get("backend") != "gum_probe":
                raise ValueError(f"{point['id']}: only entry probes may be merged")
            if point["id"] in point_ids:
                raise ValueError(f"duplicate point id: {point['id']}")
            point_ids.add(point["id"])
            points.append(point)
        slots = max(slots, plan["resources"]["slots_per_point"])
        max_bytes = max(max_bytes, plan["resources"]["max_record_bytes"])
    used_sources = set()
    for point in points:
        used_sources.update(point.get("evidence", []))
        for read in point.get("reads", []):
            used_sources.update(read.get("evidence", []))
    sources = {alias: value for alias, value in sources.items() if alias in used_sources}
    merged = {"schema": "uc.capture-plan.v1", "plan_id": plan_id, "plan_revision": 1,
              "modules": modules, "sources": sources,
              "resources": {"slots_per_point": slots, "max_record_bytes": max_bytes},
              "points": points, "merged_from": source_rows}
    result = validate(merged, verify_sources=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(merged))
    report = {"schema": "uc.entry-plan-merge-result.v1", "output": str(output),
              "sha256": file_hash(output), "plan_hash": result["plan_hash"],
              "source_plans": len(source_rows), "points": len(points)}
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, action="append", required=True)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def invoke():
        try:
            return run([path.resolve() for path in args.plan], args.plan_id, args.out.resolve())
        except Exception as error:
            write_failure(args.out, "merge_entry_plans", error,
                          {"plans": [str(path) for path in args.plan], "plan_id": args.plan_id})
            raise
    run_main(invoke)
