"""Qualify, compile and run a two-entry plan on the owned fixture process."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT));sys.path.insert(0, str(ROOT / "tests"))

from native_integration import Host, records
from d0ctl import finish_capture
from entry_analyze import analyze_run
from entryctl import prepare_apply
from p1_make_entry_qualification import run as make_entries
from uc.model import canonical
from uc.probe_pair import compile_probe_pair


def function(fid, module_sha, entry, exit):
    contract = {"probe_semantics": "pre_instruction", "return_value_stable": True,
        "xmm_return_stable": True, "stack_restored": True, "caller_return_slot_valid": True,
        "stack_adjust_remaining": 0, "nonvolatile_restore_remaining": [],
        "relocation_class": "pure_epilogue", "exception_neutral_relocation": None,
        "contract_evidence": ["fixture"]}
    return {"function_id": fid, "module": "fixture", "module_sha256": module_sha,
        "entry_rva": entry["rva"], "entry_expected_prefix": entry["expected_prefix"],
        "runtime_functions": [{"runtime_function_role": "primary"}], "terminal_sites": [],
        "normal_exits": [{"exit_site_id": fid + "-ret", "ret_rva": exit["rva"] + 15,
            "terminal_semantics": "normal_return", "terminal_semantics_verified": True,
            "probe_candidates": [{"candidate_for_minimum_span": 16, "probe_rva": exit["rva"],
                "ret_rva": exit["rva"] + 15, "available_span_through_ret": 16,
                "expected_bytes": exit["expected_prefix"][:32],
                "verified_source_prefix": exit["expected_prefix"],
                "instruction_rvas": [exit["rva"], exit["rva"] + 15],
                "incoming_edges_complete": False, "backend_patch_contract": None,
                "exit_capture_contract": contract}]}],
        "completeness": {"normal_exit_set_complete": True, "tail_set_complete": True,
                         "cold_fragments_complete": True}}


def main():
    root = ROOT / "test-output" / ("native-multi-entry-" + uuid.uuid4().hex)
    root.mkdir(parents=True);host = Host(root / "host")
    result = {"ok": False, "game_runtime_verified": False}
    try:
        targets = host.info["targets"]
        manifest = {"schema": "uc.native-exit-manifest.v1", "status": "partially-verified",
            "sources": [{"kind": "module", "alias": "fixture", "path": host.info["module_path"],
                         "sha256": host.info["sha256"]}], "summary": {},
            "backend_capability": {"backend": "gum_instruction_probe",
                "backend_build_hash": "23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475",
                "redirect_span_is_schema_constant": False},
            "functions": [function("pair", host.info["sha256"], targets["pair_entry"], targets["pair_exit"]),
                          function("recursive", host.info["sha256"], targets["pair_recursive_entry"],
                                   targets["pair_recursive_exit"]),
                          function("block", host.info["sha256"], targets["pair_block_entry"],
                                   targets["pair_block_exit"])]}
        manifest_path = root / "manifest.json";manifest_path.write_bytes(canonical(manifest))
        source_plan = {"schema": "uc.capture-plan.v1", "plan_id": "fixture-multi-entry",
            "plan_revision": 1, "modules": {"fixture": {"image": host.info["module"],
                                                          "sha256": host.info["sha256"]}},
            "sources": {"fixture": {"path": host.info["module_path"], "sha256": host.info["sha256"]}},
            "resources": {"slots_per_point": 256, "max_record_bytes": 4096}, "points": []}
        for fid, target in (("pair", targets["pair_entry"]), ("recursive", targets["pair_recursive_entry"]),
                            ("block", targets["pair_block_entry"])):
            point = {"id": fid, "backend": "gum_probe", "module": "fixture",
                "rva": target["rva"], "expected_prefix": target["expected_prefix"], "evidence": ["fixture"],
                "reads": [{"id": "raw-entry-stack-window", "base": "rsp", "op": "block", "size": 128,
                           "phase": "enter", "evidence": ["fixture"]}]}
            if fid == "pair":
                point["retention"] = {"mode": "first_per_entry_return_address", "max_keys": 16}
            source_plan["points"].append(point)
        source_plan_path = root / "source-plan.json";source_plan_path.write_bytes(canonical(source_plan))
        prepared = root / "prepared";make_entries(manifest_path, source_plan_path, prepared)
        qualification = json.loads((prepared / "qualification.json").read_text(encoding="utf-8"))
        run = root / "run"
        orchestration = prepare_apply(host.info["pid"], prepared / "qualification.json",
                                      manifest_path, source_plan_path, run)
        report = json.loads((run / "derived/report.json").read_text(encoding="utf-8"))
        plan = json.loads(Path(report["entry_plan"]["path"]).read_text(encoding="utf-8"))
        compiled = compile_probe_pair(plan, verify_sources=True)
        if host.invoke("pair", add=2)["value"] != 12:
            raise AssertionError("pair behavior changed")
        host.invoke("pair_recursive", depth=2)
        stopped = finish_capture(host.info["pid"], run, wait_seconds=5)
        acceptance = analyze_run(run, root / "acceptance")
        campaign_run = root / "campaign-run"
        campaign_unit = campaign_run / "units" / "fixture-multi-entry"
        campaign_unit.mkdir(parents=True)
        for name in ("site-qualification-evidence.json", "finish-result.json"):
            shutil.copy2(run / name, campaign_run / name)
        for name in ("activation-response.json", "result.json"):
            shutil.copy2(run / name, campaign_unit / name)
        shutil.copytree(run / "derived", campaign_unit / "derived")
        campaign_intent = json.loads((run / "intent.json").read_text(encoding="utf-8"))
        campaign_intent["complete_label"] = campaign_intent.pop("finish_label")
        (campaign_unit / "intent.json").write_bytes(canonical(campaign_intent))
        campaign_acceptance = analyze_run(campaign_run, root / "campaign-acceptance",
                                          unit_id="fixture-multi-entry")
        rows = [event for event, _ in records(stopped["directory"])]
        by_point = {point: [row for row in rows if row["point"] == point]
                    for point in ("pair/entry", "recursive/entry")}
        if len(by_point["pair/entry"]) != 1 or len(by_point["recursive/entry"]) != 3:
            raise AssertionError(by_point)
        if any(row["kind"] != "probe" for values in by_point.values() for row in values):
            raise AssertionError(by_point)
        acceptance_points = {row["function_id"]: row for row in acceptance["points"]}
        if acceptance_points["block"]["status"] != "NOT_OBSERVED_IN_COVERED_WINDOW":
            raise AssertionError(acceptance_points)
        if acceptance_points["pair"]["resolved_runtime_callsite_count"] != 1:
            raise AssertionError(acceptance_points["pair"])
        if acceptance_points["pair"]["status"] != "OBSERVED_AGGREGATED_CALLERS" or \
                acceptance_points["pair"]["retention_generation"]["scope"] != "activation_generation" or \
                acceptance_points["pair"]["evidence_scope"] != "activation_generation":
            raise AssertionError(acceptance_points["pair"])
        if acceptance_points["recursive"]["resolved_runtime_callsite_count"] != 3:
            raise AssertionError(acceptance_points["recursive"])
        if not campaign_acceptance["accepted"] or \
                campaign_acceptance["run"]["unit_path"] != str(campaign_unit.resolve()):
            raise AssertionError(campaign_acceptance)
        result = {"ok": True, "qualified_sites": orchestration["qualification_sites"],
            "logical_observations": len(plan["observations"]), "physical_sites": len(compiled.sites),
            "generation": orchestration["generation"], "events": sum(map(len, by_point.values())),
            "stopped_clean": stopped["state"] == "STOPPED_CLEAN",
            "entry_evidence_accepted": acceptance["accepted"],
            "aggregated_caller_analysis_accepted": True,
            "campaign_layout_analysis_accepted": True,
            "runtime_return_address_callsites_resolved": 4,
            "unobserved_point_not_misclassified": True, "game_runtime_verified": False}
    finally:
        host.close()
        report_path = root / "report.json"
        report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report_path), **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
