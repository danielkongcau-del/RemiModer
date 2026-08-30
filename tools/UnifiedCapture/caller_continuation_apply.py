"""Apply target-process continuation qualification to an exact-caller plan."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def run(plan_path: Path, candidates_path: Path, evidence_path: Path, output: Path) -> dict:
    plan_path, candidates_path, evidence_path, output = (Path(value).resolve() for value in
                                                          (plan_path, candidates_path, evidence_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    plan, candidates, envelope = _load(plan_path), _load(candidates_path), _load(evidence_path)
    if plan.get("schema") != "uc.capture-plan.v2":
        raise ValueError("caller continuation activation requires capture-plan v2")
    compile_probe_pair(plan)
    if candidates.get("schema") != "uc.caller-continuation-candidates.v1":
        raise ValueError("caller continuation candidate schema")
    if candidates.get("source_plan", {}).get("sha256") != file_hash(plan_path):
        raise ValueError("candidate source plan differs")
    if envelope.get("schema") != "uc.target-site-qualification-evidence.v1":
        raise ValueError("qualification evidence envelope schema")
    request, response = envelope["request"], envelope["response"]
    validate_site_qualification(request)
    if not response.get("ok") or response.get("capture_generation_published"):
        raise ValueError("qualification failed or published a capture generation")
    requested = {row["id"]: row for row in request["sites"]}
    observed = {row["id"]: row for row in response.get("sites", [])}
    expected = {row["id"] for row in candidates["sites"]}
    if set(requested) != expected or set(observed) != expected:
        raise ValueError("qualification does not exactly cover continuation candidates")
    process_identities = []
    for candidate in candidates["sites"]:
        sid = candidate["id"]
        source, result = requested[sid], observed[sid]
        expected_tuple = (candidate["module"], candidate["return_rva"], candidate["expected_prefix"])
        if (source["module"], source["rva"], source["verified_source_prefix"]) != expected_tuple or \
                (result["module"], result["rva"], result["verified_source_prefix"]) != expected_tuple:
            raise ValueError(f"{sid}: qualification identity differs from candidate")
        if not result.get("source_restoration_verified") or not result.get("target_site_patch_verified"):
            raise ValueError(f"{sid}: patch/restore qualification incomplete")
        patch = result["backend_patch_contract"]
        if patch["required_redirect_span"] not in source["safe_redirect_spans"] or \
                patch["relocated_span"] > source["semantic_safe_span"]:
            raise ValueError(f"{sid}: installed redirect exceeds source contract")
        process_identities.append(patch["target_process_identity"])
    if any(identity != process_identities[0] for identity in process_identities[1:]):
        raise ValueError("continuation sites belong to different process instances")

    result = copy.deepcopy(plan)
    candidate_source = "caller-continuation-candidates"
    qualification_source = "caller-continuation-qualification"
    for source_id in (candidate_source, qualification_source):
        if source_id in result["sources"]:
            raise ValueError(f"source id already exists: {source_id}")
    result["sources"][candidate_source] = {"path": str(candidates_path), "sha256": file_hash(candidates_path)}
    result["sources"][qualification_source] = {"path": str(evidence_path), "sha256": file_hash(evidence_path)}
    points = {row["id"]: row for row in result["observations"]}
    sites_by_observation: dict[str, list[dict]] = {}
    for candidate in candidates["sites"]:
        qualified = observed[candidate["id"]]
        for point_id in candidate["observations"]:
            if point_id not in points:
                raise ValueError(f"candidate refers to unknown observation: {point_id}")
            point = points[point_id]
            identity = (candidate["module"], candidate["return_rva"])
            exact = {(row["module"], int(row["return_rva"]))
                     for row in point.get("retention", {}).get("exact_callers", [])}
            if identity not in exact:
                raise ValueError(f"candidate is not an exact caller gate: {point_id}/{candidate['id']}")
            site = {key: copy.deepcopy(candidate[key]) for key in
                    ("id", "module", "return_rva", "expected_prefix", "predecessor_call", "source_contract")}
            site["backend_patch_contract"] = qualified["backend_patch_contract"]
            site["capture_contract"] = {
                "probe_semantics": "pre_instruction",
                "completion_semantics": "normal_return_to_observed_callsite_continuation",
                "same_thread_pairing": True,
                "exceptional_exit_observed": False,
                "return_value_stable": True,
                "xmm_return_stable": True,
            }
            site["evidence"] = list(dict.fromkeys([
                *candidate.get("source_evidence", []), candidate_source, qualification_source]))
            sites_by_observation.setdefault(point_id, []).append(site)
    for point_id, sites in sites_by_observation.items():
        point = points[point_id]
        point["completion"] = {"mode": "caller_continuation",
                               "sites": sorted(sites, key=lambda row: (row["module"], row["return_rva"]))}
        point["exit_capture_requirement"] = "completion"
    result["plan_id"] = plan["plan_id"] + "-caller-continuations"
    result["plan_revision"] = int(plan["plan_revision"]) + 1
    result["process_binding"] = process_identities[0]
    compiled = compile_probe_pair(result)
    output.mkdir(parents=True)
    plan_out = output / "capture-plan.caller-continuations.json"
    plan_out.write_bytes(canonical(result))
    report = {
        "schema": "uc.caller-continuation-application-report.v1",
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "candidates": {"path": str(candidates_path), "sha256": file_hash(candidates_path)},
        "qualification": {"path": str(evidence_path), "sha256": file_hash(evidence_path)},
        "plan": {"path": str(plan_out), "sha256": file_hash(plan_out), "plan_hash": compiled.plan_hash},
        "process_binding": process_identities[0],
        "physical_sites": len(compiled.sites),
        "continuation_sites": len(candidates["sites"]),
        "paired_observations": len(sites_by_observation),
        "semantics": "normal-return-to-observed-callsite-continuation; exceptional/nonlocal exits remain unknown",
        "activation_ready_for_bound_process": True,
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--qualification-evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.plan, args.candidates, args.qualification_evidence, args.out)
