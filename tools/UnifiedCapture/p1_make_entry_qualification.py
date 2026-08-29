"""Create one source-bound target qualification request for a v1 entry-probe plan."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest
from uc.site_qualification import validate_site_qualification


def run(manifest_path: Path, plan_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(manifest)
    if plan.get("schema") != "uc.capture-plan.v1":
        raise ValueError("source entry plan must be v1")
    functions = {row["function_id"]: row for row in manifest["functions"]}
    modules = {row["alias"]: row for row in manifest["sources"] if row.get("kind") == "module"}
    images = {}
    prepared = []
    interiors = defaultdict(set)
    for point in plan["points"]:
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
    request = {"schema": "uc.probe-site-qualification.v1",
        "qualification_id": "entry-plan-" + plan["plan_id"] + "-r" + str(plan["plan_revision"]),
        "modules": {alias: {"image": Path(modules[alias]["path"]).name,
                             "sha256": plan["modules"][alias]["sha256"]}
                    for alias in sorted({point["module"] for point in plan["points"]})},
        "sites": sites}
    validate_site_qualification(request)
    output.mkdir(parents=True)
    request_path = output / "qualification.json"
    request_path.write_bytes(canonical(request))
    report = {"schema": "uc.entry-qualification-preparation.v1", "activation_ready": False,
        "game_runtime_verified": False, "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "source_manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "request": {"path": str(request_path), "sha256": file_hash(request_path)},
        "sites": len(sites), "modules": sorted(request["modules"]),
        "remaining_after_qualification": ["target-process patch contracts", "behavior execution",
                                            "type/owner/entity correlation"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), **report}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.plan.resolve(), args.out.resolve())
