"""Prove the native Animator-to-stage ownership path from preserved Unity bytes.

This tool deliberately stops before claiming a process-instance join.  It
records the exact field write and direct calls which make the missing runtime
value explicit: native Animator A stores consumer S at A+0x6a0; S enters the
consumer callback/evaluator; the evaluator invokes cff6f0, whose machine-array
entries are passed to the two observed stage functions.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


FUNCTIONS = ("0xc9e140", "0xccec40", "0xcd1e40", "0xcff6f0")


def _instructions(document: dict[str, Any], function: str) -> list[dict[str, Any]]:
    row = document.get("functions", {}).get(function)
    if not isinstance(row, dict):
        raise ValueError(f"missing native function {function}")
    return [ins for fragment in row.get("fragments", [])
            for ins in fragment.get("instructions", [])]


def _exact(instructions: list[dict[str, Any]], rva: int, mnemonic: str,
           operands: str) -> dict[str, Any]:
    rows = [row for row in instructions if int(row.get("rva", -1)) == rva]
    if len(rows) != 1:
        raise ValueError(f"instruction {rva:#x} is not unique")
    row = rows[0]
    if row.get("mnemonic") != mnemonic or row.get("operands") != operands:
        raise ValueError(f"instruction changed at {rva:#x}: {row}")
    return {key: row[key] for key in ("rva", "bytes", "mnemonic", "operands")}


def run(native_path: Path, unity_path: Path, output: Path) -> dict[str, Any]:
    native_path, unity_path, output = native_path.resolve(), unity_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    document = json.loads(native_path.read_text(encoding="utf-8-sig"))
    if document.get("sourceSha256") != file_hash(unity_path):
        raise ValueError("native evidence and UnityPlayer identity differ")
    instruction_sets = {name: _instructions(document, name) for name in FUNCTIONS}

    witnesses = {
        "animator_to_consumer": [
            _exact(instruction_sets["0xc9e140"], 0xC9E14B, "mov", "rbx, rcx"),
            _exact(instruction_sets["0xc9e140"], 0xC9E232, "mov", "rsi, rax"),
            _exact(instruction_sets["0xc9e140"], 0xC9E281, "mov",
                   "qword ptr [rbx + 0x6a0], rsi"),
        ],
        "consumer_callback_to_evaluator": [
            _exact(instruction_sets["0xccec40"], 0xCCEC53, "mov", "rbx, rcx"),
            _exact(instruction_sets["0xccec40"], 0xCCECCA, "mov", "rcx, rbx"),
            _exact(instruction_sets["0xccec40"], 0xCCECCD, "call", "0x180cd1e40"),
        ],
        "evaluator_to_machine": [
            _exact(instruction_sets["0xcd1e40"], 0xCD20F6, "mov", "rcx, rsi"),
            _exact(instruction_sets["0xcd1e40"], 0xCD210A, "call", "0x180cff6f0"),
        ],
        "machine_to_stage_cd4c80": [
            _exact(instruction_sets["0xcff6f0"], 0xCFF711, "mov", "r15, r8"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF820, "mov",
                   "rax, qword ptr [r15 + 0x10]"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF824, "mov",
                   "rcx, qword ptr [rax]"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF827, "mov",
                   "rcx, qword ptr [rcx + rbx*8]"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF82B, "call", "0x180cd4c80"),
        ],
        "machine_to_stage_cd9640": [
            _exact(instruction_sets["0xcff6f0"], 0xCFF71A, "mov", "r8, rcx"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF7E7, "mov",
                   "r13, qword ptr [rcx]"),
            _exact(instruction_sets["0xcff6f0"], 0xCFF7EA, "add", "r13, rcx"),
            _exact(instruction_sets["0xcff6f0"], 0xD0005B, "mov",
                   "rax, qword ptr [r13 + 0x10]"),
            _exact(instruction_sets["0xcff6f0"], 0xD0006A, "mov",
                   "rcx, qword ptr [rax]"),
            _exact(instruction_sets["0xcff6f0"], 0xD0006D, "mov",
                   "rcx, qword ptr [rcx + r12*8]"),
            _exact(instruction_sets["0xcff6f0"], 0xD00071, "call", "0x180cd9640"),
        ],
    }
    result = {
        "schema": "uc.animator-stage-receiver-static-join.v1",
        "sources": {
            "native_evidence": {"path": str(native_path), "sha256": file_hash(native_path)},
            "unity_module": {"path": str(unity_path), "sha256": file_hash(unity_path)},
            "tool": {"path": str(Path(__file__).resolve()), "sha256": file_hash(Path(__file__))},
        },
        "witnesses": witnesses,
        "static_path": [
            "native Animator A stores newly constructed consumer S at A+0x6a0",
            "consumer callback 0xccec40 preserves entry RCX as S and calls 0xcd1e40 with RCX=S",
            "0xcd1e40 constructs machine inputs from S-owned fields and calls 0xcff6f0",
            "0xcff6f0 obtains stage objects from its machine arrays and calls 0xcd4c80/0xcd9640",
        ],
        "bounded_conclusion": (
            "Stage objects are children selected from S-owned evaluation inputs; their addresses "
            "are not expected to equal native Animator A or consumer S."),
        "runtime_value_still_required": (
            "In one process generation, read S=[A+0x6a0] for the selected Remielle native "
            "Animator and observe 0xccec40 with RCX=S around the stage events.  Static bytes do "
            "not manufacture that per-process equality."),
        "complete_controller": False,
    }
    output.mkdir(parents=True)
    artifact = output / "animator-stage-receiver-static-join.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.animator-stage-receiver-static-join-report.v1",
              "artifact": {"path": str(artifact), "sha256": file_hash(artifact)},
              "witness_groups": len(witnesses), "runtime_value_still_required": True}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-evidence", type=Path, required=True)
    parser.add_argument("--unity-module", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    def invoke():
        try:
            return run(args.native_evidence, args.unity_module, args.out)
        except Exception as error:
            write_failure(args.out, "animator_stage_receiver_static_join", error,
                          {key: str(value) for key, value in vars(args).items()})
            raise

    run_main(invoke)
