"""Mechanically classify and join indirect calls in the 188-type Ability ledger.

Exact identities are promoted only when a harvested runtime METHOD entry is an
unambiguous native wrapper stub for the same RIP-relative slot.  File-backed
pointers, unresolved runtime slots, object/vtable slots, and register calls are
kept as distinct evidence classes.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_FRONTIER = ROOT / "extracted/analysis/ability-executor-dependency-frontier-20260831-v1/ability-executor-dependency-frontier.json"
DEFAULT_LEDGER = ROOT / "extracted/analysis/ability-executor-coverage-ledger-20260831-v1/ability-executor-coverage-ledger.json"
DEFAULT_NATIVE_EVIDENCE = ROOT / "extracted/analysis/behavior-observer/task-executors-20260827-verified/native-evidence.json"
DEFAULT_CLASS_LAYOUT = ROOT / "extracted/analysis/class-layout.md"
RIP_MEMORY = re.compile(r"qword ptr \[rip ([+-]) (0x[0-9a-fA-F]+)\]")
REG_MEMORY = re.compile(r"qword ptr \[([a-z0-9]+) \+ (0x[0-9a-fA-F]+)\]")
REGISTER = re.compile(r"[a-z][a-z0-9]+")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _signed_rip_target(site_rva: int, size: int, operands: str) -> int | None:
    match = RIP_MEMORY.fullmatch(operands)
    if not match:
        return None
    displacement = int(match.group(2), 0)
    if match.group(1) == "-":
        displacement = -displacement
    return site_rva + size + displacement


def _stub_slot(pe: NativePE, method_rva: int) -> tuple[int, str] | None:
    """Return a slot only for one of the two exact generated wrapper forms."""
    try:
        raw = pe.bytes_at(method_rva, 16)
    except (ValueError, struct.error):
        return None
    instructions = list(pe.cs.disasm(raw, pe.image_base + method_rva))
    if instructions and instructions[0].mnemonic == "jmp":
        slot = _signed_rip_target(method_rva, instructions[0].size, instructions[0].op_str)
        if slot is not None:
            return slot, "RIP_MEMORY_JUMP"
    if (len(instructions) >= 2 and instructions[0].mnemonic == "mov"
            and instructions[0].op_str.startswith("rax, qword ptr [rip ")
            and instructions[1].mnemonic == "jmp" and instructions[1].op_str == "rax"):
        operand = instructions[0].op_str.split(", ", 1)[1]
        slot = _signed_rip_target(method_rva, instructions[0].size, operand)
        if slot is not None:
            return slot, "RIP_LOAD_THEN_JUMP_RAX"
    return None


def _method_stub_catalog(pe: NativePE, paths: Iterable[Path]) -> dict[int, list[dict[str, Any]]]:
    result: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for path in paths:
        classes: dict[str, tuple[str, str]] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            fields = line.split("|")
            if len(fields) >= 5 and fields[0] == "CLASS" and "=" not in fields[1]:
                classes[fields[1]] = (fields[3], fields[4])
                continue
            if fields and fields[0] == "CLASS":
                values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
                if "label" in values and "name" in values:
                    classes[values["label"]] = (values.get("namespace", "<unknown>"), values["name"])
                continue
            if len(fields) >= 5 and fields[0] == "METHOD" and "=" not in fields[1]:
                owner_key, method_name = fields[1], fields[3]
                try:
                    ordinal = int(fields[2], 0)
                    method_rva = int(fields[4], 0)
                except ValueError:
                    continue
            elif fields and fields[0] == "METHOD":
                values = dict(field.split("=", 1) for field in fields[1:] if "=" in field)
                if not {"label", "index", "name", "rva"} <= values.keys():
                    continue
                owner_key, method_name = values["label"], values["name"]
                try:
                    ordinal = int(values["index"], 0)
                    method_rva = int(values["rva"], 0)
                except ValueError:
                    continue
            else:
                continue
            joined = _stub_slot(pe, method_rva)
            if joined is None:
                continue
            slot_rva, form = joined
            namespace, class_name = classes.get(owner_key, ("<unknown>", owner_key))
            identity = {
                "namespace": namespace, "class": class_name, "method": method_name,
                "ordinal": ordinal, "method_rva": method_rva, "stub_form": form,
                "source": str(path.resolve()), "line": line_number,
            }
            if identity not in result[slot_rva]:
                result[slot_rva].append(identity)
    return result


def _base_relocations(pe: NativePE) -> set[int]:
    pe_offset = struct.unpack_from("<I", pe.data, 0x3C)[0]
    optional = pe_offset + 24
    relocation_rva, relocation_size = struct.unpack_from("<II", pe.data, optional + 112 + 5 * 8)
    if not relocation_rva or not relocation_size:
        return set()
    cursor = pe.offset(relocation_rva)
    end = cursor + relocation_size
    result: set[int] = set()
    while cursor + 8 <= end:
        page_rva, block_size = struct.unpack_from("<II", pe.data, cursor)
        if block_size < 8 or cursor + block_size > end:
            break
        for index in range((block_size - 8) // 2):
            entry = struct.unpack_from("<H", pe.data, cursor + 8 + index * 2)[0]
            if entry >> 12 == 10:  # IMAGE_REL_BASED_DIR64
                result.add(page_rva + (entry & 0xFFF))
        cursor += block_size
    return result


def _disk_slot(pe: NativePE, relocations: set[int], slot_rva: int) -> dict[str, Any]:
    try:
        value = struct.unpack("<Q", pe.bytes_at(slot_rva, 8))[0]
    except (ValueError, struct.error):
        return {"status": "UNBACKED_RUNTIME_SLOT", "file_value": None, "dir64_relocation": False}
    result: dict[str, Any] = {
        "status": "FILE_BACKED_OTHER_VALUE", "file_value": value,
        "dir64_relocation": slot_rva in relocations,
    }
    if slot_rva in relocations and pe.image_base <= value < pe.image_base + pe.size_of_image:
        result.update({"status": "STATIC_RELOCATED_IMAGE_POINTER", "target_rva": value - pe.image_base})
    elif value < pe.size_of_image:
        result["status"] = "RVA_LIKE_VALUE_WITHOUT_DIR64_RELOCATION"
    return result


def _instruction_context(pe: NativePE, site_rva: int, before: int = 8, after: int = 3) -> list[dict[str, Any]]:
    owner = pe.containing(site_rva)
    if owner is None:
        return []
    instructions = pe.decode(owner)["instructions"]
    positions = {row["rva"]: index for index, row in enumerate(instructions)}
    index = positions.get(site_rva)
    if index is None:
        return []
    keep = instructions[max(0, index - before):index + after + 1]
    return [{key: row.get(key) for key in ("rva", "bytes", "mnemonic", "operands", "regs_read", "regs_write")}
            for row in keep]


def _register_aliases(register: str) -> set[str]:
    if register.startswith("r") and register[1:].isdigit():
        return {register, register + "d", register + "w", register + "b"}
    families = {
        "rax": {"rax", "eax", "ax", "al", "ah"}, "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"}, "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rsi": {"rsi", "esi", "si", "sil"}, "rdi": {"rdi", "edi", "di", "dil"},
        "rbp": {"rbp", "ebp", "bp", "bpl"}, "rsp": {"rsp", "esp", "sp", "spl"},
    }
    for values in families.values():
        if register in values:
            return values
    return {register}


def _nearest_linear_writer(instructions: list[dict[str, Any]], index: int, register: str) -> dict[str, Any] | None:
    aliases = _register_aliases(register)
    for row in reversed(instructions[:index]):
        if aliases.intersection(row.get("regs_write", [])):
            return row
    return None


def _dispatch_dataflow(pe: NativePE, site_rva: int, dispatch_form: str,
                       fields: dict[str, Any]) -> dict[str, Any]:
    owner = pe.containing(site_rva)
    if owner is None:
        return {"status": "NO_PDATA_OWNER"}
    instructions = pe.decode(owner)["instructions"]
    positions = {row["rva"]: index for index, row in enumerate(instructions)}
    index = positions.get(site_rva)
    if index is None:
        return {"status": "CALLSITE_NOT_IN_LINEAR_DECODE"}
    target_register = fields.get("base_register") or fields.get("target_register")
    writer = _nearest_linear_writer(instructions, index, target_register)
    result: dict[str, Any] = {
        "status": "NEAREST_LINEAR_WRITER_ONLY_NOT_CFG_DOMINANCE",
        "nearest_target_register_writer": ({key: writer.get(key) for key in
            ("rva", "bytes", "mnemonic", "operands", "regs_read", "regs_write")} if writer else None),
    }
    if dispatch_form == "OBJECT_OR_VTABLE_SLOT" and writer is not None:
        expected = re.fullmatch(
            rf"{re.escape(target_register)}, qword ptr \[([a-z0-9]+)\]", writer["operands"])
        offset = int(fields["byte_offset"])
        if expected and offset >= 0xD0 and (offset - 0xD0) % 8 == 0:
            result.update({
                "status": "IL2CPP_CLASS_VTABLE_SLOT_SHAPE",
                "object_register": expected.group(1),
                "audited_vtable_base_offset": 0xD0,
                "vtable_slot": (offset - 0xD0) // 8,
                "caveat": "object dynamic class identity is not established by this local shape",
            })
    elif dispatch_form == "REGISTER_TARGET" and writer is not None:
        writer_parts = writer["operands"].split(", ", 1)
        if len(writer_parts) == 2 and writer_parts[0] == target_register:
            rip_slot = _signed_rip_target(writer["rva"], len(bytes.fromhex(writer["bytes"])), writer_parts[1])
            if rip_slot is not None:
                result.update({
                    "status": "REGISTER_TARGET_LOADED_FROM_RIP_SLOT",
                    "slot_rva": rip_slot,
                    "caveat": "slot identity still requires wrapper or initialized-process evidence",
                })
                return result
            dynamic_vtable = re.fullmatch(
                rf"{re.escape(target_register)}, qword ptr \[([a-z0-9]+) \+ ([a-z0-9]+)\*8 \+ 0xd0\]",
                writer["operands"])
            if dynamic_vtable:
                result.update({
                    "status": "IL2CPP_DYNAMIC_VTABLE_SLOT_SHAPE",
                    "class_register": dynamic_vtable.group(1),
                    "slot_index_register": dynamic_vtable.group(2),
                    "audited_vtable_base_offset": 0xD0,
                    "caveat": "runtime slot index and dynamic class identity are not established",
                })
                return result
        match = re.fullmatch(
            rf"{re.escape(target_register)}, qword ptr \[([a-z0-9]+) \+ (0x[0-9a-fA-F]+|[0-9]+)\]",
            writer["operands"])
        if match:
            result.update({
                "status": "REGISTER_TARGET_LOADED_FROM_RECORD_FIELD",
                "record_base_register": match.group(1),
                "record_field_offset": int(match.group(2), 0),
                "caveat": "record owner and callee identity are not established by nearest linear writer",
            })
    return result


def _classification(operands: str) -> tuple[str, dict[str, Any]]:
    match = REG_MEMORY.fullmatch(operands)
    if match:
        return "OBJECT_OR_VTABLE_SLOT", {"base_register": match.group(1), "byte_offset": int(match.group(2), 0)}
    if REGISTER.fullmatch(operands):
        return "REGISTER_TARGET", {"target_register": operands}
    return "OTHER_INDIRECT_FORM", {}


def _unresolved_slot_account(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count unresolved storage identities without conflating callsite forms.

    A register-target call can load the same runtime slot used by a direct
    RIP-memory call.  The union is therefore the useful capture-plan bound;
    summing the two categories would over-count that overlap.
    """
    rip_callsite_slots = {
        int(row["slot_rva"])
        for row in records
        if row.get("dispatch_form") == "RIP_GLOBAL_SLOT"
        and row.get("resolution_status") == "UNRESOLVED_RIP_SLOT_IDENTITY"
    }
    register_loaded_slots = {
        int(row["local_dataflow"]["slot_rva"])
        for row in records
        if (row.get("local_dataflow") or {}).get("status")
        == "REGISTER_TARGET_LOADED_FROM_RIP_SLOT"
    }
    return {
        "unresolved_rip_callsite_slots": len(rip_callsite_slots),
        "register_loaded_rip_slots": len(register_loaded_slots),
        "unique_runtime_slot_candidates_without_exact_identity": len(
            rip_callsite_slots | register_loaded_slots),
    }


def build(frontier_path: Path, ledger_path: Path, native_evidence_path: Path,
          class_layout_path: Path, method_catalog_paths: tuple[Path, ...], out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    frontier = _load(frontier_path)
    ledger = _load(ledger_path)
    native_evidence = _load(native_evidence_path)
    if frontier.get("schema") != "uc.ability-executor-dependency-frontier.v1":
        raise ValueError("unsupported dependency frontier")
    if ledger.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported Ability executor ledger")
    if len(frontier.get("indirect_callsites", [])) != 353:
        raise ValueError("expected the bounded 353-callsite frontier")
    game_path = Path(ledger["sources"]["game_module"]["path"])
    if file_hash(game_path) != ledger["sources"]["game_module"]["sha256"]:
        raise ValueError("GameAssembly source identity changed")
    for path in method_catalog_paths + (native_evidence_path, class_layout_path):
        if not path.is_file():
            raise FileNotFoundError(path)
    pe = NativePE(game_path)
    relocations = _base_relocations(pe)
    stub_catalog = _method_stub_catalog(pe, method_catalog_paths)
    preserved = {int(key, 0): value for key, value in native_evidence.get("namedWrapperSlots", {}).items()}

    records = []
    counts: Counter[str] = Counter()
    exact_semantic = 0
    exact_static_target = 0
    vtable_shape = 0
    register_record_field = 0
    register_rip_slot = 0
    register_dynamic_vtable = 0
    unique_rip_slots: set[int] = set()
    exact_semantic_slots: set[int] = set()
    for call in frontier["indirect_callsites"]:
        site_rva = int(call["site_rva"])
        instruction_size = len(bytes.fromhex(call["bytes"]))
        rip_slot = _signed_rip_target(site_rva, instruction_size, call["operands"])
        record = dict(call)
        if rip_slot is not None:
            unique_rip_slots.add(rip_slot)
            stub_identities = stub_catalog.get(rip_slot, [])
            preserved_names = preserved.get(rip_slot, [])
            disk = _disk_slot(pe, relocations, rip_slot)
            if stub_identities or preserved_names:
                status = "EXACT_WRAPPER_SLOT_IDENTITY"
                exact_semantic += 1
                exact_semantic_slots.add(rip_slot)
            elif disk["status"] == "STATIC_RELOCATED_IMAGE_POINTER":
                status = "EXACT_STATIC_TARGET_WITHOUT_SEMANTIC_IDENTITY"
                exact_static_target += 1
            else:
                status = "UNRESOLVED_RIP_SLOT_IDENTITY"
            record.update({
                "dispatch_form": "RIP_GLOBAL_SLOT", "slot_rva": rip_slot,
                "resolution_status": status, "wrapper_stub_identities": stub_identities,
                "preserved_wrapper_names": preserved_names, "disk_slot": disk,
            })
        else:
            dispatch_form, fields = _classification(call["operands"])
            dataflow = _dispatch_dataflow(pe, site_rva, dispatch_form, fields)
            if dataflow["status"] == "IL2CPP_CLASS_VTABLE_SLOT_SHAPE":
                vtable_shape += 1
            elif dataflow["status"] == "REGISTER_TARGET_LOADED_FROM_RECORD_FIELD":
                register_record_field += 1
            elif dataflow["status"] == "REGISTER_TARGET_LOADED_FROM_RIP_SLOT":
                register_rip_slot += 1
            elif dataflow["status"] == "IL2CPP_DYNAMIC_VTABLE_SLOT_SHAPE":
                register_dynamic_vtable += 1
            record.update({"dispatch_form": dispatch_form, "resolution_status": "STATIC_TARGET_UNRESOLVED", **fields,
                           "local_dataflow": dataflow,
                           "instruction_context": _instruction_context(pe, site_rva)})
        counts[record["dispatch_form"]] += 1
        records.append(record)

    unresolved_slots = _unresolved_slot_account(records)
    summary = {
        "indirect_callsites": len(records),
        "dispatch_form_counts": dict(sorted(counts.items())),
        "unique_rip_slots": len(unique_rip_slots),
        "exact_semantic_wrapper_callsites": exact_semantic,
        "exact_semantic_wrapper_slots": len(exact_semantic_slots),
        "exact_static_target_without_semantic_identity_callsites": exact_static_target,
        "object_callsites_with_il2cpp_class_vtable_shape": vtable_shape,
        "register_callsites_loaded_from_record_field": register_record_field,
        "register_callsites_loaded_from_rip_slot": register_rip_slot,
        "register_callsites_with_dynamic_il2cpp_vtable_shape": register_dynamic_vtable,
        "remaining_without_exact_target_identity": len(records) - exact_semantic - exact_static_target,
        **unresolved_slots,
    }
    artifact = {
        "schema": "uc.ability-executor-indirect-call-join.v1",
        "sources": {
            "dependency_frontier": _source(frontier_path), "ability_executor_coverage": _source(ledger_path),
            "game_module": _source(game_path), "preserved_native_evidence": _source(native_evidence_path),
            "audited_il2cpp_class_layout": _source(class_layout_path),
            "method_catalogs": [_source(path) for path in method_catalog_paths],
        },
        "summary": summary,
        "bounded_conclusions": [
            "wrapper identities require an exact same-slot generated method stub or preserved native-evidence slot name",
            "a DIR64-backed preferred-image pointer proves a static target RVA but not its semantic identity",
            "RVA-like file values without a DIR64 relocation are not promoted to runtime call targets",
            "object/vtable and register calls retain local instruction context but no guessed callee",
            "vtable slot numbers use the independently audited Il2CppClass +0xD0 base only when the local class-pointer load shape is present",
            "unbacked image slots require an initialized process or an independently proven registration relation for further resolution",
        ],
        "runtime_needed_now": False,
        "callsites": sorted(records, key=lambda row: (row["caller_type"], row["caller_method"], row["site_rva"])),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-executor-indirect-call-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-executor-indirect-call-join-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary, "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frontier", type=Path, default=DEFAULT_FRONTIER)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--native-evidence", type=Path, default=DEFAULT_NATIVE_EVIDENCE)
    parser.add_argument("--class-layout", type=Path, default=DEFAULT_CLASS_LAYOUT)
    parser.add_argument("--method-catalog", action="append", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    catalogs = tuple(path.resolve() for path in (args.method_catalog or sorted((ROOT / "extracted").glob("*method*.txt"))))
    try:
        return build(args.frontier.resolve(), args.ledger.resolve(), args.native_evidence.resolve(),
                     args.class_layout.resolve(), catalogs, args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_executor_indirect_call_join", error, {
            "frontier": str(args.frontier), "ledger": str(args.ledger),
            "native_evidence": str(args.native_evidence), "method_catalogs": [str(path) for path in catalogs],
            "class_layout": str(args.class_layout),
        })
        raise


if __name__ == "__main__":
    run_main(main)
