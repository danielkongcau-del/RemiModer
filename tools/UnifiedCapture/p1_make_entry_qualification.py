"""Create one source-bound target qualification request for v1 entry plans.

Multiple source plans may be supplied.  Their physical entry sites are
qualified once, while the original plans remain separate activation units.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest
from uc.site_qualification import validate_site_qualification


def _plan_paths(value):
    if isinstance(value, (str, Path)):
        return [Path(value)]
    return [Path(path) for path in value]


def run(manifest_path: Path, plan_path: Path | list[Path], output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    plan_paths = [path.resolve() for path in _plan_paths(plan_path)]
    if not plan_paths:
        raise ValueError("at least one source entry plan is required")
    plans = [json.loads(path.read_text(encoding="utf-8-sig")) for path in plan_paths]
    validate_exit_manifest(manifest)
    module_contracts = {}
    points = []
    point_ids = set()
    for path, plan in zip(plan_paths, plans):
        if plan.get("schema") != "uc.capture-plan.v1":
            raise ValueError(f"{path}: source entry plan must be v1")
        if not plan.get("points"):
            raise ValueError(f"{path}: source entry plan has no points")
        for alias, module in plan.get("modules", {}).items():
            if alias in module_contracts and module_contracts[alias] != module:
                raise ValueError(f"{path}: module alias {alias} has a conflicting identity")
            module_contracts[alias] = module
        for point in plan["points"]:
            if point.get("backend") != "gum_probe":
                raise ValueError(f"{path}:{point.get('id')}: campaign qualification accepts entry probes only")
            if point["id"] in point_ids:
                raise ValueError(f"duplicate campaign point id: {point['id']}")
            point_ids.add(point["id"])
            points.append(point)
    functions = {row["function_id"]: row for row in manifest["functions"]}
    modules = {row["alias"]: row for row in manifest["sources"] if row.get("kind") == "module"}
    images = {}
    prepared = []
    interiors = defaultdict(set)
    for point in points:
        function = functions.get(point["id"])
        if function is None:
            raise ValueError(f"{point['id']}: no matching native manifest function")
        if function["module"] != point["module"]:
            raise ValueError(f"{point['id']}: module mismatch")
        module = function["module"]
        source = modules[module]
        image = images.setdefault(module, NativePE(Path(source["path"])))
        if file_hash(image.path) != function["module_sha256"]:
            raise ValueError(f"{module}: source module identity changed")
        entry_rva = function["entry_rva"]
        prefix = image.bytes_at(entry_rva, 32)
        span = 0
        instructions = []
        for instruction in image.cs.disasm(prefix, image.image_base + entry_rva):
            row = {"rva": instruction.address - image.image_base, "size": instruction.size,
                   "mnemonic": instruction.mnemonic, "operands": instruction.op_str}
            instructions.append(row)
            span += instruction.size
            if span >= 16:
                break
        if span < 16:
            raise ValueError(f"{point['id']}: entry lacks a 16-byte instruction-boundary window")
        interiors[module].update(range(entry_rva + 1, entry_rva + span))
        prepared.append((point, function, prefix, span, instructions))
    edges = {module: image.direct_control_xrefs(interiors[module]) for module, image in images.items()}
    sites = []
    for point, function, prefix, span, instructions in prepared:
        begin = function["entry_rva"]
        inside = [edge for edge in edges[function["module"]] if begin < edge["target_rva"] < begin + span]
        if inside:
            raise ValueError(f"{point['id']}: direct control edge enters entry relocation window")
        sites.append({"id": point["id"] + "/entry", "module": function["module"], "rva": begin,
            "verified_source_prefix": prefix.hex(), "semantic_safe_span": span,
            "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True,
            "static_evidence": {"instruction_boundary_span": span, "instructions": instructions,
                "direct_edge_scan_scope": "all-file-backed-executable-sections",
                "direct_interior_edges": []}})
    source_rows = [{"plan_id": plan["plan_id"], "plan_revision": plan["plan_revision"],
                    "path": str(path), "sha256": file_hash(path)}
                   for path, plan in zip(plan_paths, plans)]
    identity = hashlib.sha256(canonical(source_rows)).hexdigest()[:16]
    request = {"schema": "uc.probe-site-qualification.v1",
        "qualification_id": "entry-campaign-" + identity,
        "modules": {alias: {"image": Path(modules[alias]["path"]).name,
                             "sha256": module_contracts[alias]["sha256"]}
                    for alias in sorted({point["module"] for point in points})},
        "sites": sites}
    validate_site_qualification(request)
    output.mkdir(parents=True)
    request_path = output / "qualification.json"
    request_path.write_bytes(canonical(request))
    campaign = {"schema": "uc.entry-campaign.v1", "campaign_id": request["qualification_id"],
        "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "qualification": {"path": str(request_path), "sha256": file_hash(request_path)},
        "units": [{"id": row["plan_id"], "order": index + 1,
                   "source_plan": {"path": row["path"], "sha256": row["sha256"]},
                   "armed_label": row["plan_id"].upper().replace("-", "_") + "_ARMED",
                   "complete_label": row["plan_id"].upper().replace("-", "_") + "_COMPLETE"}
                  for index, row in enumerate(source_rows)]}
    campaign_path = output / "campaign.json"
    campaign_path.write_bytes(canonical(campaign))
    report = {"schema": "uc.entry-qualification-preparation.v2", "activation_ready": False,
        "game_runtime_verified": False, "source_plans": source_rows,
        "source_manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "request": {"path": str(request_path), "sha256": file_hash(request_path)},
        "campaign": {"path": str(campaign_path), "sha256": file_hash(campaign_path)},
        "sites": len(sites), "modules": sorted(request["modules"]),
        "remaining_after_qualification": ["target-process patch contracts", "behavior execution",
                                            "type/owner/entity correlation"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), **report}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True, action="append",
                        help="repeat to qualify several activation plans in one target-process pass")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), [path.resolve() for path in args.plan], args.out.resolve())
