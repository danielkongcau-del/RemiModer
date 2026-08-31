from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p1_apply_instruction_qualification import run


BUILD_HASH = "23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475"


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_near_only_instruction_qualification_emits_manifestless_v2(tmp_path: Path):
    module = tmp_path / "game.dll"
    source_bytes = bytes.fromhex("e811223344" + "90" * 27)
    module.write_bytes(source_bytes)
    module_hash = hashlib.sha256(source_bytes).hexdigest()
    prefix = source_bytes.hex()
    source_plan = {
        "schema": "uc.capture-plan.v1",
        "plan_id": "instruction-fixture",
        "plan_revision": 1,
        "modules": {"game": {"image": "game.dll", "sha256": module_hash}},
        "sources": {"static": {"path": str(module), "sha256": module_hash}},
        "resources": {"slots_per_point": 256, "max_record_bytes": 2048,
                      "capture_xmm": False},
        "points": [{"id": "callsite", "backend": "gum_probe", "module": "game",
                    "rva": 0, "expected_prefix": prefix, "reads": [],
                    "evidence": ["static"], "capture_purpose": "fixture"}],
    }
    request = {
        "schema": "uc.probe-site-qualification.v1",
        "qualification_id": "instruction-fixture-q",
        "modules": source_plan["modules"],
        "sites": [{"id": "callsite/entry", "module": "game", "rva": 0,
                   "verified_source_prefix": prefix, "semantic_safe_span": 6,
                   "safe_redirect_spans": [5], "direct_interior_edge_free": True}],
    }
    identity = {"pid": 7, "creation_time_100ns": 11}
    patch = {
        "backend_build_hash": BUILD_HASH, "redirect_kind": "near",
        "required_redirect_span": 5, "relocated_span": 6,
        "fault_in_relocated_span_test": "passed-own-fixture",
        "architectural_rsp_test": "passed-own-fixture",
        "cet_cfg_test": "target-runtime-required", "probe_rva": 0,
        "target_process_identity": identity,
    }
    response = {
        "schema": "uc.target-site-qualification-result.v1", "ok": True,
        "qualification_id": request["qualification_id"],
        "capture_generation_published": False,
        "sites": [{**request["sites"][0], "source_restoration_verified": True,
                   "target_site_patch_verified": True,
                   "backend_patch_contract": patch}],
    }
    plan_path = _write(tmp_path / "source-plan.json", source_plan)
    evidence_path = _write(tmp_path / "qualification-evidence.json", {
        "schema": "uc.target-site-qualification-evidence.v1",
        "request": request, "response": response,
    })
    report = run(plan_path, evidence_path, tmp_path / "out")
    qualified = json.loads(Path(report["instruction_plan"]["path"]).read_text())
    observation = qualified["observations"][0]
    assert report["activation_ready"] is True
    assert report["exit_probes_activated"] is False
    assert observation["instruction_site_id"] == "callsite"
    assert observation["exit_capture_requirement"] == "none"
    assert "native_exit_manifest" not in observation
    assert observation["entry"]["backend_patch_contract"]["required_redirect_span"] == 5


def test_instruction_qualification_rejects_request_point_mismatch(tmp_path: Path):
    module = tmp_path / "game.dll"
    source_bytes = bytes.fromhex("e811223344" + "90" * 27)
    module.write_bytes(source_bytes)
    module_hash = hashlib.sha256(source_bytes).hexdigest()
    prefix = source_bytes.hex()
    plan = {
        "schema": "uc.capture-plan.v1", "plan_id": "mismatch", "plan_revision": 1,
        "modules": {"game": {"image": "game.dll", "sha256": module_hash}},
        "sources": {"static": {"path": str(module), "sha256": module_hash}},
        "resources": {"slots_per_point": 16, "max_record_bytes": 128,
                      "capture_xmm": False},
        "points": [{"id": "callsite", "backend": "gum_probe", "module": "game",
                    "rva": 0, "expected_prefix": prefix, "reads": [],
                    "evidence": ["static"]}],
    }
    request = {"schema": "uc.probe-site-qualification.v1",
        "qualification_id": "mismatch-q", "modules": plan["modules"],
        "sites": [{"id": "callsite/entry", "module": "game", "rva": 1,
                   "verified_source_prefix": prefix, "semantic_safe_span": 6,
                   "safe_redirect_spans": [5], "direct_interior_edge_free": True}]}
    patch = {"backend_build_hash": BUILD_HASH, "redirect_kind": "near",
        "required_redirect_span": 5, "relocated_span": 6,
        "fault_in_relocated_span_test": "passed-own-fixture",
        "architectural_rsp_test": "passed-own-fixture",
        "cet_cfg_test": "target-runtime-required", "probe_rva": 1,
        "target_process_identity": {"pid": 7, "creation_time_100ns": 11}}
    response = {"schema": "uc.target-site-qualification-result.v1", "ok": True,
        "qualification_id": "mismatch-q", "capture_generation_published": False,
        "sites": [{**request["sites"][0], "source_restoration_verified": True,
                   "target_site_patch_verified": True,
                   "backend_patch_contract": patch}]}
    with __import__("pytest").raises(ValueError, match="differs from source point"):
        run(_write(tmp_path / "plan.json", plan),
            _write(tmp_path / "evidence.json", {
                "schema": "uc.target-site-qualification-evidence.v1",
                "request": request, "response": response}), tmp_path / "out")
