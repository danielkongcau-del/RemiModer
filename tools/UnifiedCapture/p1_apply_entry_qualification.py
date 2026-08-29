"""Compile a target-qualified multi-entry v2 plan without enabling exits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import validate_exit_manifest
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def validate_qualification_scope(requested: dict, observed: dict, expected_ids: set[str],
                                 allow_qualification_superset: bool):
    """Validate transport completeness separately from sub-plan selection."""
    if set(requested) != set(observed):
        raise ValueError("qualification response does not exactly cover its request")
    if allow_qualification_superset:
        if not expected_ids <= set(observed):
            raise ValueError("qualification result does not cover every source plan entry")
    elif set(observed) != expected_ids:
        raise ValueError("qualification result does not exactly cover source plan entries")


def run(manifest_path: Path, plan_path: Path, evidence_path: Path, output: Path,
        exit_requirement: str = "none", allow_qualification_superset: bool = False):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    source_plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    envelope = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(manifest)
    if source_plan.get("schema") != "uc.capture-plan.v1":
        raise ValueError("source entry plan must be v1")
    if envelope.get("schema") != "uc.target-site-qualification-evidence.v1":
        raise ValueError("qualification evidence envelope schema")
    request, response = envelope["request"], envelope["response"]
    validate_site_qualification(request)
    if not response.get("ok") or response.get("capture_generation_published"):
        raise ValueError("qualification failed or published a generation")
    requested = {row["id"]: row for row in request["sites"]}
    observed = {row["id"]: row for row in response["sites"]}
    expected_ids = {point["id"] + "/entry" for point in source_plan["points"]}
    validate_qualification_scope(requested, observed, expected_ids, allow_qualification_superset)
    process_identities = []
    for site_id, result in observed.items():
        source = requested[site_id]
        if any(result[key] != source[key] for key in ("module", "rva", "verified_source_prefix")):
            raise ValueError(f"{site_id}: target result differs from request")
        if not result.get("source_restoration_verified") or not result.get("target_site_patch_verified"):
            raise ValueError(f"{site_id}: target install/restoration not verified")
        patch = result["backend_patch_contract"]
        if patch["required_redirect_span"] not in source["safe_redirect_spans"] or patch["relocated_span"] > source["semantic_safe_span"]:
            raise ValueError(f"{site_id}: target patch exceeds semantic window")
        process_identities.append(patch["target_process_identity"])
    if any(identity != process_identities[0] for identity in process_identities[1:]):
        raise ValueError("qualified entry sites belong to different process instances")
    functions = {row["function_id"]: row for row in manifest["functions"]}
    module_sources = {row["alias"]: row for row in manifest["sources"] if row.get("kind") == "module"}
    source_table = {
        "target-qualification": {"path": str(evidence_path), "sha256": file_hash(evidence_path)}
    }
    for alias in sorted({point["module"] for point in source_plan["points"]}):
        source_table[alias + "-module"] = {"path": module_sources[alias]["path"],
                                           "sha256": module_sources[alias]["sha256"]}
    observations = []
    for point in source_plan["points"]:
        function = functions[point["id"]]
        result = observed[point["id"] + "/entry"]
        reads = []
        for read in point.get("reads", []):
            if read.get("phase") != "enter":
                raise ValueError(f"{point['id']}: entry-only plan cannot preserve leave reads")
            read_copy = dict(read)
            read_copy["evidence"] = [point["module"] + "-module", "target-qualification"]
            reads.append(read_copy)
        observation={"id": point["id"] + "/entry", "backend": "gum_function_probe_pair",
            "module": point["module"],
            "entry": {"rva": function["entry_rva"], "expected_prefix": function["entry_expected_prefix"],
                      "backend_patch_contract": result["backend_patch_contract"], "reads": reads},
            # Exit capture is opt-in: the native probe-pair machinery is ready,
            # but activating exits additionally requires the derived manifest
            # to carry fully qualified exit candidates (compile enforces it).
            "exit_capture_requirement": exit_requirement,
            "native_exit_manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path),
                                     "function_id": point["id"]},
            "evidence": [point["module"] + "-module", "target-qualification"]}
        if "retention" in point:
            observation["retention"] = dict(point["retention"])
        observations.append(observation)
    plan = {"schema": "uc.capture-plan.v2", "plan_id": "target-qualified-" + source_plan["plan_id"],
        "plan_revision": source_plan["plan_revision"], "process_binding": process_identities[0],
        "modules": {alias: source_plan["modules"][alias]
                    for alias in sorted({point["module"] for point in source_plan["points"]})},
        "sources": source_table,
        "resources": {"event_slots_per_observation": max(256, source_plan.get("resources", {}).get("slots_per_point", 0)),
                      "call_frames_per_function": 8, "thread_nesting_limit": 256,
                      "max_record_bytes": max(4096, source_plan.get("resources", {}).get("max_record_bytes", 0))},
        "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                 "partial_overlap": "reject"},
        "observations": observations}
    compiled = compile_probe_pair(plan, verify_sources=True)
    output.mkdir(parents=True)
    plan_out = output / "entry-plan.target-qualified.json"
    plan_out.write_bytes(canonical(plan))
    report = {"schema": "uc.entry-qualification-application.v1", "process_bound": True,
        "entry_activation_ready": True, "game_runtime_verified": False,
        "exit_requirement_requested": exit_requirement,
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "qualification_evidence": {"path": str(evidence_path), "sha256": file_hash(evidence_path)},
        "entry_plan": {"path": str(plan_out), "sha256": file_hash(plan_out), "plan_hash": compiled.plan_hash},
        "logical_observations": len(observations), "physical_sites": len(compiled.sites),
        "qualification_sites_total": len(observed), "qualification_sites_used": len(expected_ids),
        "qualification_superset_accepted": allow_qualification_superset,
        "exit_probes_activated": exit_requirement != "none"}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), **report}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--exit-requirement", choices=("none", "completion", "return_value", "path_identity"),
                        default="none",
                        help="promote observations to probe-pairs with exit capture when the "
                             "derived manifest carries fully qualified exit candidates")
    parser.add_argument("--allow-qualified-superset", action="store_true",
                        help="allow one process-bound qualification envelope to cover this plan plus other plans")
    args = parser.parse_args()
    def invoke():
        try:
            return run(args.manifest.resolve(), args.plan.resolve(), args.evidence.resolve(),
                       args.out.resolve(), args.exit_requirement, args.allow_qualified_superset)
        except Exception as error:
            write_failure(args.out, "apply_entry_qualification", error,
                          {"manifest": str(args.manifest), "plan": str(args.plan),
                           "evidence": str(args.evidence), "exit_requirement": args.exit_requirement,
                           "allow_qualification_superset": args.allow_qualified_superset})
            raise
    run_main(invoke)
