"""Audit whether the native BehaviorManager scheduler dispatches Task.OnReset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _slot(methods: list[dict[str, Any]], name: str) -> int:
    rows = {row.get("slot") for row in methods if row.get("name") == name}
    if len(rows) != 1:
        raise ValueError(f"method slot is not unique: {name}")
    return int(rows.pop())


def _offset_operand(offset: int) -> str:
    return f"+ {offset:#x}]"


def _decode_pdata_less_head(image: NativePE, rva: int) -> list[dict[str, Any]]:
    raw = image.bytes_at(rva, 64)
    rows = []
    for ins in image.cs.disasm(raw, image.image_base + rva):
        direct_target = None
        if ins.mnemonic in ("jmp", "ret"):
            rows.append({"rva": ins.address - image.image_base, "mnemonic": ins.mnemonic,
                         "operands": ins.op_str, "direct_target_rva": direct_target})
            return rows
        rows.append({"rva": ins.address - image.image_base, "mnemonic": ins.mnemonic,
                     "operands": ins.op_str, "direct_target_rva": direct_target})
    raise ValueError(f"pdata-less method has no bounded terminal in 64 bytes: {rva:#x}")


def run(native_evidence: Path, module: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    evidence = json.loads(native_evidence.read_text(encoding="utf-8-sig"))
    methods = evidence["methodInventory"]
    on_start_slot = _slot(methods, "SetBoolParameter.OnStart.1")
    on_end_slot = _slot(methods, "Task.OnEnd.19")
    complete_slot = _slot(methods, "Task.OnBehaviorComplete.25")
    reset_slot = _slot(methods, "Task.OnReset.26")
    image = NativePE(module)

    push_owner = image.containing(0x1E465B41)
    if push_owner is None:
        raise ValueError("PushTask OnStart callsite owner is missing")
    push_call = next((row for row in image.decode(push_owner)["instructions"]
                      if row["rva"] == 0x1E465B41), None)
    if push_call is None or push_call["mnemonic"] != "call" or (
            "+ 0x100]" not in push_call["operands"]):
        raise ValueError("PushTask OnStart virtual callsite changed")
    vtable_base = 0x100 - on_start_slot * 8
    offsets = {
        "OnStart": vtable_base + on_start_slot * 8,
        "OnEnd": vtable_base + on_end_slot * 8,
        "OnBehaviorComplete": vtable_base + complete_slot * 8,
        "OnReset": vtable_base + reset_slot * 8,
    }

    manager_methods = [row for row in methods if row.get("name", "").startswith("BehaviorManager.")]
    owners: dict[int, Any] = {}
    pdata_less = []
    for row in manager_methods:
        owner = image.containing(row["rva"])
        if owner is None:
            pdata_less.append(row)
        else:
            owners[owner.begin] = owner
    decoded_functions = []
    for owner in owners.values():
        decoded = image.decode(owner)
        if not decoded["all_declared_bytes_decoded"]:
            raise ValueError(f"incomplete BehaviorManager PDATA decode: {owner.begin:#x}")
        decoded_functions.append((owner.begin, decoded["instructions"], "pdata"))
    for row in pdata_less:
        decoded_functions.append((row["rva"], _decode_pdata_less_head(image, row["rva"]),
                                  "bounded-head"))

    dispatch = {name: [] for name in offsets}
    for owner_rva, instructions, extent in decoded_functions:
        for row in instructions:
            if row["mnemonic"] != "call":
                continue
            for name, offset in offsets.items():
                if _offset_operand(offset) in row["operands"]:
                    dispatch[name].append({"owner_rva": owner_rva, "callsite_rva": row["rva"],
                                           "operand": row["operands"], "extent": extent})

    if dispatch["OnReset"]:
        raise ValueError("BehaviorManager contains an OnReset virtual dispatch")
    if not dispatch["OnEnd"] or not dispatch["OnBehaviorComplete"]:
        raise ValueError("runtime lifecycle control dispatches were not recovered")
    artifact = {
        "schema": "uc.task-reset-dispatch-audit.v1",
        "sources": {
            "native_evidence": {"path": str(native_evidence), "sha256": file_hash(native_evidence)},
            "game_module": {"path": str(module), "sha256": file_hash(module)},
        },
        "slot_binding": {
            "vtable_base_offset": vtable_base,
            "push_task_on_start_callsite_rva": 0x1E465B41,
            "methods": {name: {"slot": slot, "vtable_offset": offsets[name]}
                        for name, slot in (("OnStart", on_start_slot), ("OnEnd", on_end_slot),
                                           ("OnBehaviorComplete", complete_slot),
                                           ("OnReset", reset_slot))},
        },
        "coverage": {
            "behavior_manager_methods": len(manager_methods),
            "unique_pdata_functions": len(owners),
            "pdata_less_bounded_heads": len(pdata_less),
            "all_pdata_functions_completely_decoded": True,
        },
        "dispatch": dispatch,
        "conclusion": {
            "behavior_manager_dispatches_on_reset": False,
            "runtime_completion_dispatches_present": True,
            "classification": "NOT_A_GAMEPLAY_REPETITION_REQUIREMENT",
        },
        "semantic_limit": "bounded to the harvested BehaviorManager method inventory; does not claim no other subsystem can invoke Task.OnReset",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(artifact))
    print(json.dumps({"ok": True, "output": str(output), "coverage": artifact["coverage"],
                      "dispatch_counts": {key: len(value) for key, value in dispatch.items()}},
                     ensure_ascii=False))
    return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-evidence", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.native_evidence.resolve(), args.module.resolve(), args.out.resolve())
