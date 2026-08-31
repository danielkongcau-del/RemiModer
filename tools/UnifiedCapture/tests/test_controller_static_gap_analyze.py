from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller_static_gap_analyze import (JOB_CONSUMER_RVA, JOB_EXECUTE_RVA, JOB_SHARED_BODY_RVA,
                                           JOB_WRAPPER_RVA, RESET_RVAS, run)
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def _fixtures(tmp_path: Path) -> tuple[Path, Path, Path]:
    names = ["SetBoolParameter.OnReset", "SetIntegerParameter.OnReset",
             "SetTriggerParameter.OnReset", "SetBoolParameter.OnReset"]
    type_ids = [34455, 34459, 41564, 71227]
    fields = [[(0x58, "target"), (0x60, "value"), (0x68, "name")],
              [(0x58, "target"), (0x60, "value"), (0x68, "name")],
              [(0x68, "name"), (0x70, "owner")],
              [(0x58, "value"), (0x70, "name"), (0x78, "owner")]]
    plan_points = []
    acceptance_points = []
    functions = []
    implicit_targets = [0x9000, 0x9010, 0x9020]
    inventory = [
        {"typeIndex": 1, "depth": 0, "name": "SharedString.op_Implicit.1", "method": "op_Implicit",
         "rva": 0x9000, "slot": 0xffff, "source": "fixture", "sourceLine": 1},
        {"typeIndex": 2, "depth": 0, "name": "SharedBool.op_Implicit.1", "method": "op_Implicit",
         "rva": 0x9010, "slot": 0xffff, "source": "fixture", "sourceLine": 2},
        {"typeIndex": 3, "depth": 0, "name": "SharedInt.op_Implicit.1", "method": "op_Implicit",
         "rva": 0x9020, "slot": 0xffff, "source": "fixture", "sourceLine": 3},
        {"typeIndex": 48226, "depth": 0, "name": "IKNHGFBHLLK.Execute.0", "method": "Execute",
         "rva": JOB_EXECUTE_RVA, "slot": 4, "source": "fixture", "sourceLine": 4},
    ]
    for index, (rva, name, type_id, layout) in enumerate(zip(RESET_RVAS, names, type_ids, fields)):
        point_id = f"{name}@0x{rva:x}"
        plan_points.append({"id": point_id, "rva": rva,
            "field_read_contract": {"authority": {"type_id": type_id, "method": "OnReset"}},
            "reads": [{"id": field, "base": "rcx", "offset": offset, "width": 8,
                       "evidence": ["runtime-field-layout"]} for offset, field in layout]})
        acceptance_points.append({"point": point_id + "/entry", "function_id": point_id,
                                  "status": "NOT_OBSERVED_IN_COVERED_WINDOW", "evidence_scope": "marked_window"})
        instructions = [{"rva": rva, "mnemonic": "mov", "operands": "rsi, rcx"}]
        # Clear the first/last pointer and assign SharedString to the name field.
        clear_offset = layout[0][0] if index < 2 else layout[-1][0]
        name_offset = next(offset for offset, field in layout if field == "name")
        instructions.extend([
            {"rva": rva + 1, "mnemonic": "mov", "operands": f"qword ptr [rsi + 0x{clear_offset:x}], 0"},
            {"rva": rva + 2, "mnemonic": "call", "operands": "x", "directTargetRva": 0x9000},
            {"rva": rva + 3, "mnemonic": "mov", "operands": f"qword ptr [rsi + 0x{name_offset:x}], rax"},
        ])
        if any(field == "value" for _, field in layout):
            value_offset = next(offset for offset, field in layout if field == "value")
            target = 0x9020 if index == 1 else 0x9010
            instructions.extend([
                {"rva": rva + 4, "mnemonic": "xor", "operands": "ecx, ecx"},
                {"rva": rva + 5, "mnemonic": "call", "operands": "x", "directTargetRva": target},
                {"rva": rva + 6, "mnemonic": "mov", "operands": f"qword ptr [rsi + 0x{value_offset:x}], rax"},
            ])
        instructions.append({"rva": rva + 7, "mnemonic": "ret", "operands": ""})
        functions.append({"rva": rva, "extent": "pdata", "allDeclaredBytesDecoded": True,
                          "names": [name + f".{index}"], "instructions": instructions})
    plan_points.append({"id": f"ParallelForJobStruct<IKNHGFBHLLK>.Execute@0x{JOB_WRAPPER_RVA:x}",
                        "rva": JOB_WRAPPER_RVA,
                        "field_read_contract": {"authority": {"closed_type": "IKNHGFBHLLK"}}, "reads": []})
    acceptance_points.append({"point": plan_points[-1]["id"] + "/entry",
                              "function_id": plan_points[-1]["id"],
                              "status": "NOT_OBSERVED_IN_COVERED_WINDOW", "evidence_scope": "marked_window"})
    functions.extend([
        {"rva": JOB_EXECUTE_RVA, "extent": "bounded-window", "allDeclaredBytesDecoded": False,
         "names": ["IKNHGFBHLLK.Execute.0"], "instructions": [
             {"rva": JOB_EXECUTE_RVA, "mnemonic": "add", "operands": "rcx, 0x10"},
             {"rva": JOB_EXECUTE_RVA + 4, "mnemonic": "jmp", "operands": "0x192df4580",
              "directTargetRva": JOB_SHARED_BODY_RVA}]},
        {"rva": JOB_WRAPPER_RVA, "extent": "pdata", "allDeclaredBytesDecoded": True,
         "names": [], "instructions": [{"rva": JOB_WRAPPER_RVA + 0x85, "mnemonic": "call",
                                           "operands": "x", "directTargetRva": JOB_SHARED_BODY_RVA}]},
        {"rva": JOB_SHARED_BODY_RVA, "extent": "pdata", "allDeclaredBytesDecoded": True,
         "names": [], "instructions": [{"rva": JOB_SHARED_BODY_RVA + 0x35, "mnemonic": "jmp",
                                           "operands": "x", "directTargetRva": JOB_CONSUMER_RVA}]},
        {"rva": JOB_CONSUMER_RVA, "extent": "pdata", "allDeclaredBytesDecoded": True,
         "names": ["ODKPBBAJAEG.KBPGJAPPBLI.45"], "instructions": []},
    ])
    return (_write(tmp_path / "plan.json", {"points": plan_points}),
            _write(tmp_path / "acceptance.json", {"points": acceptance_points}),
            _write(tmp_path / "native.json", {"methodInventory": inventory, "functions": functions}))


def test_static_reset_and_job_semantics_are_kept_separate_from_runtime(tmp_path: Path) -> None:
    plan, acceptance, native = _fixtures(tmp_path)
    result = run(plan, acceptance, native, tmp_path / "out")
    assert result["checks"] == {
        "reset_implementation_count": 4,
        "all_reset_implementations_source_verified": True,
        "all_reset_entries_not_observed": True,
        "parallel_job_static_chain_source_verified": True,
        "parallel_job_wrapper_not_observed": True,
    }
    first = result["reset_implementations"][0]
    assert [row["field"] for row in first["normal_path_field_operations"]] == ["target", "name", "value"]
    assert first["normal_path_field_operations"][-1]["input_zeroed"] is True
    assert result["parallel_job_dispatch"]["concrete_execute_thunk"]["jumps_to_rva"] == JOB_SHARED_BODY_RVA


def test_incomplete_reset_decode_is_rejected(tmp_path: Path) -> None:
    plan, acceptance, native = _fixtures(tmp_path)
    value = json.loads(native.read_text(encoding="utf-8"))
    value["functions"][0]["allDeclaredBytesDecoded"] = False
    _write(native, value)
    with pytest.raises(ValueError, match="complete PDATA decode"):
        run(plan, acceptance, native, tmp_path / "out")


def test_unknown_call_result_identity_is_rejected(tmp_path: Path) -> None:
    plan, acceptance, native = _fixtures(tmp_path)
    value = json.loads(native.read_text(encoding="utf-8"))
    value["methodInventory"] = [row for row in value["methodInventory"] if row["rva"] != 0x9000]
    _write(native, value)
    with pytest.raises(ValueError, match="harvested identity"):
        run(plan, acceptance, native, tmp_path / "out")
