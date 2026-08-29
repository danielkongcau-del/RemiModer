"""Derive a new activation-unit layout while reusing an exact site qualification."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate
from uc.native_manifest import validate_exit_manifest
from uc.site_qualification import validate_site_qualification


def _load_ref(ref: dict, label: str):
    path = Path(ref["path"]).resolve()
    if file_hash(path) != ref["sha256"]:
        raise ValueError(f"{label} changed: {path}")
    return path, json.loads(path.read_text(encoding="utf-8-sig"))


def run(campaign_path: Path, plan_paths: list[Path], output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    base = json.loads(campaign_path.read_text(encoding="utf-8-sig"))
    if base.get("schema") != "uc.entry-campaign.v1":
        raise ValueError("entry campaign schema")
    _, qualification = _load_ref(base["qualification"], "campaign qualification")
    validate_site_qualification(qualification)
    _, manifest = _load_ref(base["manifest"], "campaign manifest")
    validate_exit_manifest(manifest)
    functions = {row["function_id"]: row for row in manifest["functions"]}
    units, expected_sites = [], {}
    for index, path in enumerate(plan_paths):
        path = path.resolve()
        plan = json.loads(path.read_text(encoding="utf-8-sig"))
        validate(plan, verify_sources=False)
        used_sources = set()
        for point in plan["points"]:
            used_sources.update(point.get("evidence", []))
            for read in point.get("reads", []):
                used_sources.update(read.get("evidence", []))
        for alias in used_sources:
            source = plan["sources"][alias]
            if file_hash(Path(source["path"])) != source["sha256"]:
                raise ValueError(f"{plan['plan_id']}: used evidence source changed: {alias}")
        for point in plan["points"]:
            if point.get("backend") != "gum_probe":
                raise ValueError(f"{point['id']}: campaign units must be entry probes")
            sid = point["id"] + "/entry"
            if sid in expected_sites:
                raise ValueError(f"point occurs in more than one reframed unit: {point['id']}")
            function = functions.get(point["id"])
            if function is None or function["module"] != point["module"] or function["entry_rva"] != point["rva"]:
                raise ValueError(f"{point['id']}: source plan differs from native manifest")
            expected_sites[sid] = (point["module"], point["rva"])
        units.append({"id": plan["plan_id"], "order": index + 1,
                      "source_plan": {"path": str(path), "sha256": file_hash(path)},
                      "armed_label": plan["plan_id"].upper().replace("-", "_") + "_ARMED",
                      "complete_label": plan["plan_id"].upper().replace("-", "_") + "_COMPLETE"})
    actual_sites = {row["id"]: (row["module"], row["rva"]) for row in qualification["sites"]}
    if actual_sites != expected_sites:
        raise ValueError("reframed unit union differs from the qualified physical entry set")
    source_ref = {"path": str(campaign_path), "sha256": file_hash(campaign_path)}
    derived = copy.deepcopy(base)
    derived["source_campaign"] = source_ref
    derived["units"] = units
    token = hashlib.sha256(canonical({"source": source_ref, "units": units})).hexdigest()[:16]
    derived["campaign_id"] = base["campaign_id"] + "-units-" + token
    output.mkdir(parents=True)
    path = output / "campaign.json"
    path.write_bytes(canonical(derived))
    report = {"schema": "uc.entry-campaign-reframe-report.v1",
              "campaign": {"path": str(path), "sha256": file_hash(path)},
              "source_campaign": source_ref, "units": len(units),
              "qualified_sites_reused": len(actual_sites),
              "unit_points": {unit["id"]: len(json.loads(Path(unit["source_plan"]["path"]).read_text(
                  encoding="utf-8-sig"))["points"]) for unit in units},
              "requires_new_target_qualification": False}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--plan", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def invoke():
        try:
            return run(args.campaign.resolve(), [path.resolve() for path in args.plan], args.out.resolve())
        except Exception as error:
            write_failure(args.out, "reframe_campaign", error,
                          {"campaign": str(args.campaign), "plans": [str(path) for path in args.plan]})
            raise
    run_main(invoke)
