"""End-to-end resumable D0 orchestration on the owned fixture process."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT));sys.path.insert(0, str(ROOT / "tests"))
from d0ctl import finish_capture, prepare_apply
from d0_analyze import analyze_run
from native_integration import Host
from uc.model import canonical, file_hash


def main():
    root = ROOT / "test-output" / ("native-d0-orchestration-" + uuid.uuid4().hex)
    root.mkdir(parents=True);host = Host(root / "host")
    result = {"ok": False, "game_runtime_verified": False}
    try:
        target = host.info["targets"]
        qualification = {"schema": "uc.probe-site-qualification.v1", "qualification_id": "fixture-d0",
            "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
            "sites": [
                {"id": "pair/entry", "module": "fixture", "rva": target["pair_entry"]["rva"],
                 "verified_source_prefix": target["pair_entry"]["expected_prefix"], "semantic_safe_span": 16,
                 "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True},
                {"id": "pair/pair-ret", "module": "fixture", "rva": target["pair_exit"]["rva"],
                 "verified_source_prefix": target["pair_exit"]["expected_prefix"], "semantic_safe_span": 16,
                 "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True}]}
        qualification_path = root / "qualification.json";qualification_path.write_bytes(canonical(qualification))
        contract = {"probe_semantics": "pre_instruction", "return_value_stable": True,
            "xmm_return_stable": True, "stack_restored": True, "caller_return_slot_valid": True,
            "stack_adjust_remaining": 0, "nonvolatile_restore_remaining": [],
            "relocation_class": "pure_epilogue", "exception_neutral_relocation": None,
            "contract_evidence": ["fixture"]}
        manifest = {"schema": "uc.native-exit-manifest.v1", "status": "partially-verified",
            "sources": [{"kind": "module", "alias": "fixture", "path": host.info["module_path"],
                         "sha256": host.info["sha256"]}], "summary": {},
            "backend_capability": {"backend": "gum_instruction_probe",
                "backend_build_hash": "23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475",
                "redirect_span_is_schema_constant": False},
            "functions": [{"function_id": "pair", "module": "fixture", "module_sha256": host.info["sha256"],
                "entry_rva": target["pair_entry"]["rva"], "entry_expected_prefix": target["pair_entry"]["expected_prefix"],
                "runtime_functions": [{"runtime_function_role": "primary"}], "terminal_sites": [],
                "normal_exits": [{"exit_site_id": "pair-ret", "ret_rva": target["pair_exit"]["rva"] + 15,
                    "terminal_semantics": "normal_return", "terminal_semantics_verified": True,
                    "probe_candidates": [{"candidate_for_minimum_span": 16, "probe_rva": target["pair_exit"]["rva"],
                        "ret_rva": target["pair_exit"]["rva"] + 15, "available_span_through_ret": 16,
                        "expected_bytes": target["pair_exit"]["expected_prefix"][:32],
                        "verified_source_prefix": target["pair_exit"]["expected_prefix"],
                        "instruction_rvas": [target["pair_exit"]["rva"], target["pair_exit"]["rva"] + 15],
                        "incoming_edges_complete": False, "backend_patch_contract": None,
                        "exit_capture_contract": contract}]}],
                "completeness": {"normal_exit_set_complete": True, "tail_set_complete": True,
                                 "cold_fragments_complete": True}}]}
        manifest_path = root / "manifest.json";manifest_path.write_bytes(canonical(manifest))
        output = root / "run"
        prepare_apply(host.info["pid"], qualification_path, manifest_path, "pair", output)
        first = json.loads((output / "result.json").read_text(encoding="utf-8"))
        prepare_apply(host.info["pid"], qualification_path, manifest_path, "pair", output)
        second = json.loads((output / "result.json").read_text(encoding="utf-8"))
        if first != second or first["generation"] != 1 or host.control("status")["generation"] != 1:
            raise AssertionError("resumed D0 repeated activation")
        if host.invoke("pair", add=4)["value"] != 14:
            raise AssertionError("entry D0 changed fixture behavior")
        stopped = finish_capture(host.info["pid"], output, wait_seconds=5)
        acceptance = analyze_run(output, root / "acceptance")
        if acceptance["resolved_runtime_callsite_count"] != 1:
            raise AssertionError(acceptance["runtime_caller_evidence"])
        caller = acceptance["runtime_caller_evidence"][0]
        if caller["callsite_status"] != "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL":
            raise AssertionError(caller)
        result = {"ok": True, "generation": 1, "resumable_without_duplicate_activation": True,
                  "process_bound_plan": True, "qualification_sites": 2,
                  "entry_event_invoked": True, "stopped_clean": stopped["state"] == "STOPPED_CLEAN",
                  "d0_evidence_accepted": acceptance["accepted"],
                  "runtime_return_address_callsite_resolved": True,
                  "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json";report.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
