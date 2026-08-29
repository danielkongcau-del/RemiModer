"""Turn a target qualification envelope into process-bound evidence and entry D0 plan.

The generated entry-only plan proves loader/backend/site compatibility.  Exit
contracts are preserved in the derived manifest but are not promoted to a
probe-pair while the selected function's cross-function indirect-entry scope
remains open.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import validate_exit_manifest
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def run(manifest_path: Path, evidence_path: Path, function_id: str, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(manifest)
    envelope = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
    if envelope.get("schema") != "uc.target-site-qualification-evidence.v1":
        raise ValueError("qualification evidence envelope schema")
    request, response = envelope["request"], envelope["response"]
    validate_site_qualification(request)
    if not response.get("ok") or response.get("schema") != "uc.target-site-qualification-result.v1":
        raise ValueError("qualification did not succeed")
    if response.get("qualification_id") != request["qualification_id"] or response.get("capture_generation_published"):
        raise ValueError("qualification identity/publication mismatch")
    requested = {row["id"]: row for row in request["sites"]}
    observed = {row["id"]: row for row in response["sites"]}
    if requested.keys() != observed.keys():
        raise ValueError("qualification site result set differs from request")
    for sid, row in observed.items():
        source = requested[sid]
        if row["module"] != source["module"] or row["rva"] != source["rva"] or \
                row["verified_source_prefix"] != source["verified_source_prefix"]:
            raise ValueError(f"{sid}: target result does not match requested source identity")
        if not row.get("source_restoration_verified") or not row.get("target_site_patch_verified"):
            raise ValueError(f"{sid}: install/restoration not verified")
        patch = row["backend_patch_contract"]
        if patch["required_redirect_span"] not in source["safe_redirect_spans"] or \
                patch["relocated_span"] > source["semantic_safe_span"]:
            raise ValueError(f"{sid}: observed patch exceeds pre-authorized semantic window")
    functions = [row for row in manifest["functions"] if row["function_id"] == function_id]
    if len(functions) != 1:
        raise ValueError("function id is not unique")
    function = functions[0]
    entry_id = function_id + "/entry"
    if entry_id not in observed:
        raise ValueError("entry site was not qualified")
    derived = copy.deepcopy(manifest)
    derived_function = next(row for row in derived["functions"] if row["function_id"] == function_id)
    patched_exits = 0
    for exit_site in derived_function["normal_exits"]:
        sid = function_id + "/" + exit_site["exit_site_id"]
        if sid not in observed:
            continue
        result = observed[sid]
        for candidate in exit_site["probe_candidates"]:
            if candidate["probe_rva"] != result["rva"]:
                continue
            candidate["backend_patch_contract"] = result["backend_patch_contract"]
            candidate["target_qualification_evidence"] = {
                "path": str(evidence_path), "sha256": file_hash(evidence_path), "site_id": sid}
            # Only the 5-byte class has executed relocation fixtures.  A far
            # target result remains useful evidence but is not promoted here.
            if result["backend_patch_contract"]["required_redirect_span"] == 5:
                candidate["exit_capture_contract"]["exception_neutral_relocation"] = True
                candidate["exit_capture_contract"]["contract_evidence"].append(
                    "sealed-own-fixture-near-pure-epilogue-class-qualification")
            patched_exits += 1
    derived["sources"].append({"kind": "target-site-qualification", "path": str(evidence_path),
                               "sha256": file_hash(evidence_path), "process_bound": True})
    derived["summary"]["target_patch_contracts_verified"] = len(observed)
    derived["summary"]["exit_patch_contracts_bound"] = patched_exits
    derived["summary"]["activation_ready_functions"] = 0
    derived["summary"]["game_runtime_verified"] = False
    output.mkdir(parents=True)
    derived_path = output / "native-exit-manifest.target-qualified.json"
    derived_path.write_bytes(canonical(derived))
    source_ids = {"game-module": {"path": next(row["path"] for row in derived["sources"]
                                                       if row.get("kind") == "module" and row.get("alias") == function["module"]),
                                  "sha256": function["module_sha256"]},
                  "target-qualification": {"path": str(evidence_path), "sha256": file_hash(evidence_path)}}
    plan = {"schema": "uc.capture-plan.v2", "plan_id": "d0-target-qualified-entry-" + function_id,
            "plan_revision": 1,
            "process_binding": observed[entry_id]["backend_patch_contract"]["target_process_identity"],
            "modules": {function["module"]: request["modules"][function["module"]]},
            "sources": source_ids,
            "resources": {"event_slots_per_observation": 256, "call_frames_per_function": 8,
                          "thread_nesting_limit": 64, "max_record_bytes": 4096},
            "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                     "partial_overlap": "reject"},
            "observations": [{"id": function_id + "/d0-entry", "backend": "gum_function_probe_pair",
                "module": function["module"],
                "entry": {"rva": function["entry_rva"], "expected_prefix": function["entry_expected_prefix"],
                          "backend_patch_contract": observed[entry_id]["backend_patch_contract"],
                          "reads": [{"id": "raw-entry-stack-window", "base": "rsp", "op": "block",
                                     "size": 128, "phase": "enter",
                                     "evidence": ["game-module", "target-qualification"]}]},
                "exit_capture_requirement": "none",
                "native_exit_manifest": {"path": str(derived_path), "sha256": file_hash(derived_path),
                                         "function_id": function_id},
                "evidence": ["game-module", "target-qualification"]}]}
    plan_path = output / "d0-entry-target-qualified.json"
    plan_path.write_bytes(canonical(plan))
    compiled = compile_probe_pair(plan, verify_sources=True)
    report = {"schema": "uc.target-qualification-application.v1", "process_bound": True,
              "target_entry_activation_ready": True, "probe_pair_activation_ready": False,
              "game_runtime_verified": False, "behavior_events_collected": False,
              "function_id": function_id, "physical_sites": len(compiled.sites),
              "derived_manifest": {"path": str(derived_path), "sha256": file_hash(derived_path)},
              "entry_plan": {"path": str(plan_path), "sha256": file_hash(plan_path),
                             "plan_hash": compiled.plan_hash},
              "remaining_pair_blockers": ["incoming indirect-entry completeness remains open",
                                           "exit activation is deliberately disabled in entry-only D0",
                                           "far relocation remains unqualified if selected"]}
    report_path = output / "report.json";report_path.write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "entry_plan": str(plan_path),
                      "plan_hash": compiled.plan_hash, "entry_activation_ready": True,
                      "pair_activation_ready": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--function-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.evidence.resolve(), args.function_id, args.out.resolve())
