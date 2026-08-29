"""Bind an entry campaign to a mechanical native callsite manifest."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import validate_callsite_manifest


def _load(ref: dict, label: str):
    path = Path(ref["path"]).resolve()
    if file_hash(path) != ref["sha256"]:
        raise ValueError(f"{label} changed: {path}")
    return path, json.loads(path.read_text(encoding="utf-8-sig"))


def run(campaign_path: Path, callsite_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    campaign = json.loads(campaign_path.read_text(encoding="utf-8-sig"))
    if campaign.get("schema") != "uc.entry-campaign.v1":
        raise ValueError("entry campaign schema")
    manifest = json.loads(callsite_path.read_text(encoding="utf-8-sig"))
    validate_callsite_manifest(manifest)
    points = {}
    stack_windows = []
    for unit in campaign["units"]:
        _, plan = _load(unit["source_plan"], f"campaign unit {unit['id']}")
        if plan.get("schema") != "uc.capture-plan.v1":
            raise ValueError(f"{unit['id']}: source plan must be v1")
        for point in plan["points"]:
            if point["id"] in points:
                raise ValueError(f"duplicate campaign point: {point['id']}")
            points[point["id"]] = point
            for read in point.get("reads", []):
                if read.get("phase", "enter") == "enter" and read.get("base") == "rsp" \
                        and read.get("op") == "block":
                    stack_windows.append({"function_id": point["id"], "bytes": read["size"]})
    targets = {row["function_id"]: row for row in manifest["targets"]}
    if len(targets) != len(manifest["targets"]):
        raise ValueError("callsite manifest function ids are not unique")
    if set(targets) != set(points):
        missing = sorted(set(points) - set(targets))
        extra = sorted(set(targets) - set(points))
        raise ValueError(f"callsite/campaign scope mismatch: missing={missing}, extra={extra}")
    rows = []
    for function_id, point in points.items():
        target = targets[function_id]
        if target["module"] != point["module"] or target["entry_rva"] != point["rva"]:
            raise ValueError(f"{function_id}: callsite target differs from source plan entry")
        rows.append({"function_id": function_id, "module": point["module"], "entry_rva": point["rva"],
                     "direct_static_site_count": target["direct_static_site_count"],
                     "runtime_indirect_resolution_required":
                         target.get("runtime_observed_callsite_required_for_indirect_dispatch", True)})
    rows.sort(key=lambda row: (row["module"], row["entry_rva"], row["function_id"]))
    callsite_ref = {"path": str(callsite_path), "sha256": file_hash(callsite_path)}
    source_ref = {"path": str(campaign_path), "sha256": file_hash(campaign_path)}
    binding = {"schema": "uc.entry-campaign-callsite-binding.v1",
        "source_campaign": source_ref, "native_callsite_manifest": callsite_ref,
        "bounded_claims": manifest.get("bounded_claims", []),
        "runtime_resolution_contract": manifest["runtime_resolution_contract"],
        "raw_abi_capture_contract": {
            "source": "UnifiedCapture gum probe callback capability; not inferred from metadata prototypes",
            "general_registers": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"],
            "xmm_register_count": 16,
            "entry_rsp_windows": stack_windows,
            "semantic_parameter_mapping": "DEFERRED"},
        "targets": rows,
        "summary": {"targets": len(rows),
            "targets_with_direct_static_sites": sum(row["direct_static_site_count"] > 0 for row in rows),
            "targets_requiring_runtime_indirect_resolution":
                sum(row["runtime_indirect_resolution_required"] for row in rows),
            "verified_direct_static_sites": sum(row["direct_static_site_count"] for row in rows),
            "targets_with_entry_rsp_window": len({row["function_id"] for row in stack_windows}),
            "semantic_callers_closed": False,
            "complete_controller": False}}
    output.mkdir(parents=True)
    binding_path = output / "callsite-binding.json"
    binding_path.write_bytes(canonical(binding))
    derived = copy.deepcopy(campaign)
    token = hashlib.sha256(canonical({"campaign": source_ref, "callsites": callsite_ref})).hexdigest()[:16]
    derived["campaign_id"] = campaign["campaign_id"] + "-callsite-" + token
    derived["source_campaign"] = source_ref
    derived["native_callsite_manifest"] = callsite_ref
    derived["callsite_binding"] = {"path": str(binding_path), "sha256": file_hash(binding_path)}
    derived_path = output / "campaign.json"
    derived_path.write_bytes(canonical(derived))
    report = {"schema": "uc.entry-campaign-callsite-binding-report.v1",
        "campaign": {"path": str(derived_path), "sha256": file_hash(derived_path)},
        "binding": {"path": str(binding_path), "sha256": file_hash(binding_path)},
        **binding["summary"]}
    report_path = output / "report.json"
    report_path.write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--callsite-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def invoke():
        try:
            return run(args.campaign.resolve(), args.callsite_manifest.resolve(), args.out.resolve())
        except Exception as error:
            write_failure(args.out, "bind_campaign_callsites", error,
                          {"campaign": str(args.campaign), "callsite_manifest": str(args.callsite_manifest)})
            raise
    run_main(invoke)
