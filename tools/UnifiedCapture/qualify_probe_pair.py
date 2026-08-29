"""Seal a local probe-pair matrix as a backend-build capability artifact."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from uc.cli import run_main, write_failure
from uc.model import file_hash


ROOT = Path(__file__).resolve().parent


def redirect_span(probe: dict) -> tuple[str, int]:
    installed = bytes.fromhex(probe["after"])
    if installed[:1] == b"\xe9":
        return "near", 5
    changed = probe.get("changed_byte_offsets", [])
    if changed and max(changed) < 16:
        return "far-or-unknown", 16
    raise ValueError("unrecognized redirect emitted by pinned Gum build")


def run(report_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"capability output is immutable: {output}")
    report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    if report.get("schema") != "uc.probe-pair-matrix.v1" or not report.get("ok"):
        raise ValueError("probe-pair matrix is not a passing source")
    required = {"probe_relocated_memory_av_caught", "probe_relocated_call_seh_caught",
                "epilogue_return_preserved", "long_epilogue_all_instruction_classes_preserved",
                "pop_epilogue_in_near_relocated_span_preserved", "target_architectural_rsp_proven",
                "cfg_policy_query_available", "cet_policy_query_available"}
    if not required <= {name for name, passed in report["checks"].items() if passed}:
        raise ValueError("required qualification checks are missing")
    observations = []
    for row in report["rows"]:
        result = row.get("result") or {}
        if "probe" not in result:
            continue
        kind, span = redirect_span(result["probe"])
        observations.append({"mode": row["mode"], "redirect_kind": kind,
                             "required_redirect_span": span,
                             "changed_byte_offsets": result["probe"]["changed_byte_offsets"],
                             "before": result["probe"]["before"], "after": result["probe"]["after"]})
    gum = ROOT / "vendor/gum-17.17.0/frida-gum.lib"
    fixture = ROOT / "build/ProbePairProbe.exe"
    sources = [ROOT / "native/probe_pair_probe.cpp", ROOT / "native/probe_pair_fixture.asm",
               ROOT / "tests/probe_pair_matrix.py", Path(__file__).resolve()]
    output.mkdir(parents=True)
    inputs = output / "inputs"
    inputs.mkdir()
    copied_report = inputs / "probe-pair-matrix-report.json"
    copied_fixture = inputs / "ProbePairProbe.exe"
    shutil.copyfile(report_path, copied_report)
    shutil.copyfile(fixture, copied_fixture)
    copied_sources = []
    for index, source in enumerate(sources):
        destination = inputs / f"source-{index:02d}-{source.name}"
        shutil.copyfile(source, destination)
        copied_sources.append(destination)
    policies = [row["result"] for row in report["rows"] if row.get("result")]
    value = {
        "schema": "uc.gum-probe-backend-capability.v1",
        "status": "passed-own-fixture-target-runtime-policy-check-required",
        "backend": "gum_instruction_probe",
        "backend_build": "frida-gum-17.17.0-windows-x86_64",
        "backend_build_hash": file_hash(gum),
        "matrix_report": {"path": str(copied_report), "sha256": file_hash(copied_report)},
        "fixture_binary": {"path": str(copied_fixture), "sha256": file_hash(copied_fixture)},
        "fixture_sources": [{"path": str(path), "sha256": file_hash(path)} for path in copied_sources],
        "redirect_observations": observations,
        "observed_redirect_spans": sorted({row["required_redirect_span"] for row in observations}),
        "far_16_byte_redirect_observed": any(row["required_redirect_span"] == 16 for row in observations),
        "relocated_span_fault_test": "passed-own-fixture",
        "relocated_call_seh_test": "passed-own-fixture",
        "pure_epilogue_return_test": "passed-own-fixture",
        "pure_epilogue_instruction_classes": {
            "classes": ["nop", "stack-adjust", "nonvolatile-pop", "ret"],
            "near_redirect_relocation": "passed-own-fixture",
            "far_redirect_relocation": "not-observed-target-runtime-required"
        },
        "architectural_rsp_test": "passed-own-fixture",
        "cfg": {"policy_query": all(row.get("cfg_policy_query") for row in policies),
                "enabled_in_fixture": any(row.get("cfg_enabled") for row in policies),
                "target_runtime_check_required": True},
        "cet_user_shadow_stack": {
            "policy_query": all(row.get("cet_user_shadow_stack_policy_query") for row in policies),
            "enabled_in_fixture": any(row.get("cet_user_shadow_stack_enabled") for row in policies),
            "strict_in_fixture": any(row.get("cet_user_shadow_stack_strict_mode") for row in policies),
            "target_runtime_check_required": True},
        "scope": {"game_runtime_verified": False,
                  "arbitrary_instruction_class_qualified": False,
                  "qualified_relocation_classes": ["faulting-memory-load", "relative-call", "pure-epilogue"]},
    }
    artifact = output / "backend-capability.json"
    artifact.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    index = {"schema": "uc.backend-capability-index.v1", "sealed": True,
             "activation_ready": False, "files": [
                 {"file": str(path.relative_to(output)), "size": path.stat().st_size, "sha256": file_hash(path)}
                 for path in sorted(output.rglob("*")) if path.is_file()]}
    (output / "evidence-index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "artifact": str(artifact),
                      "observed_redirect_spans": value["observed_redirect_spans"],
                      "game_runtime_verified": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def invoke():
        try:
            return run(args.report.resolve(), args.out.resolve())
        except Exception as error:
            write_failure(args.out, "qualify_probe_pair", error, {"report": str(args.report)})
            raise
    run_main(invoke)
