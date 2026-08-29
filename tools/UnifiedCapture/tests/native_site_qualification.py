"""Verify target-process site qualification without publishing a generation."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from native_integration import Host
from uc.model import canonical


def main():
    root = ROOT / "test-output" / ("native-site-qualification-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    host = Host(root)
    result = {"ok": False, "game_runtime_verified": False}
    try:
        targets = host.info["targets"]
        qualification = {"schema": "uc.probe-site-qualification.v1",
            "qualification_id": "own-fixture-entry-exit",
            "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
            "sites": []}
        for name in ("pair_entry", "pair_exit"):
            target = targets[name]
            qualification["sites"].append({"id": name, "module": "fixture", "rva": target["rva"],
                "verified_source_prefix": target["expected_prefix"], "semantic_safe_span": 16,
                "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True})
        response = host.control("qualify-sites", qualification=qualification,
                                request_id="qualification-fixture-1")
        repeated = host.control("qualify-sites", qualification=qualification,
                                request_id="qualification-fixture-1")
        if response != repeated or response["capture_generation_published"] or response["behavior_events_collected"]:
            raise AssertionError(response)
        if len(response["sites"]) != 2 or any(not row["source_restoration_verified"] for row in response["sites"]):
            raise AssertionError(response)
        if any(row["backend_patch_contract"]["required_redirect_span"] not in (5, 16)
               for row in response["sites"]):
            raise AssertionError(response)
        if host.control("status")["generation"] != 0:
            raise AssertionError("qualification published a generation")
        if host.invoke("pair", add=9)["value"] != 19:
            raise AssertionError("qualified function was not restored")
        entry = response["sites"][0]
        manifest = {"schema": "uc.native-exit-manifest.v1", "status": "three-way-verified",
            "functions": [{"function_id": "pair", "module": "fixture", "entry_rva": targets["pair_entry"]["rva"],
                "runtime_functions": [{"runtime_function_role": "primary"}], "normal_exits": [],
                "terminal_sites": [], "completeness": {"normal_exit_set_complete": False,
                    "tail_set_complete": False, "cold_fragments_complete": False}}]}
        manifest_path = root / "entry-only-manifest.json";manifest_path.write_bytes(canonical(manifest))
        plan = {"schema": "uc.capture-plan.v2", "plan_id": "qualified-entry-fixture", "plan_revision": 1,
            "modules": {"fixture": {"image": host.info["module"], "sha256": host.info["sha256"]}},
            "sources": {"fixture": {"path": host.info["module_path"], "sha256": host.info["sha256"]}},
            "resources": {"event_slots_per_observation": 16, "call_frames_per_function": 4,
                          "thread_nesting_limit": 16, "max_record_bytes": 128},
            "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                     "partial_overlap": "reject"},
            "observations": [{"id": "pair-entry", "backend": "gum_function_probe_pair", "module": "fixture",
                "entry": {"rva": targets["pair_entry"]["rva"],
                          "expected_prefix": targets["pair_entry"]["expected_prefix"],
                          "backend_patch_contract": entry["backend_patch_contract"], "reads": []},
                "exit_capture_requirement": "none", "native_exit_manifest": {"path": str(manifest_path),
                    "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "function_id": "pair"},
                "evidence": ["fixture"]}]}
        applied = host.control("apply", plan=plan)
        if applied["generation"] != 1 or host.invoke("pair", add=1)["value"] != 20:
            raise AssertionError("process-bound patch contract was not reusable")
        host.stop()
        result = {"ok": True, "sites": len(response["sites"]),
                  "redirect_spans": [row["backend_patch_contract"]["required_redirect_span"]
                                     for row in response["sites"]],
                  "restoration_verified": True, "idempotent_request": True,
                  "qualification_generation_published": False,
                  "process_bound_contract_reused_by_apply": True, "game_runtime_verified": False}
    finally:
        host.close()
        report = root / "report.json"
        report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report), **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
