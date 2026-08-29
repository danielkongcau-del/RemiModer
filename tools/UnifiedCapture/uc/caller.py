"""Mechanical entry-stack return-address and predecessor-call resolution."""
from __future__ import annotations

import struct
from typing import Any

from .native_manifest import NativePE


def entry_return_address(event: dict[str, Any], blob: bytes) -> dict[str, Any] | None:
    read = next((row for row in event.get("reads", [])
                 if row.get("id") == "raw-entry-stack-window" and row.get("status") == 1
                 and row.get("length", 0) >= 8), None)
    if read is None:
        return None
    begin = read.get("offset")
    if not isinstance(begin, int) or begin < 0 or begin + 8 > len(blob):
        return None
    value = struct.unpack_from("<Q", blob, begin)[0]
    rsp = event.get("raw_abi", {}).get("registers", {}).get("rsp")
    return {
        "return_address": value,
        "stack_read_address": read.get("address"),
        "rsp": rsp,
        "stack_slot_matches_rsp": read.get("address") == rsp,
        "source": "first-eight-bytes-of-successful-raw-entry-stack-window",
    }


def resolve_callsite(return_evidence: dict[str, Any], binding: dict[str, Any], image: NativePE) -> dict[str, Any]:
    result = dict(return_evidence)
    module_base = binding.get("module_base")
    address = return_evidence["return_address"]
    if not isinstance(module_base, int) or not (module_base <= address < module_base + image.size_of_image):
        result["module_membership"] = "OUTSIDE_BOUND_MODULE"
        result["callsite_status"] = "UNRESOLVED"
        return result
    return_rva = address - module_base
    result.update({"module_membership": "INSIDE_BOUND_MODULE", "return_rva": return_rva})
    owner = image.containing(return_rva - 1) if return_rva else None
    if owner is None:
        result["callsite_status"] = "NO_PDATA_OWNER_FOR_RETURN_PREDECESSOR"
        return result
    decoded = image.decode(owner)
    predecessors = [ins for ins in decoded["instructions"] if ins["rva"] + ins["size"] == return_rva]
    result["caller_runtime_function"] = {
        "begin_rva": owner.begin, "end_rva": owner.end, "unwind_rva": owner.unwind_rva,
        "all_declared_bytes_decoded": decoded["all_declared_bytes_decoded"],
    }
    if len(predecessors) != 1:
        result["callsite_status"] = "PREDECESSOR_INSTRUCTION_NOT_UNIQUE"
        result["predecessor_count"] = len(predecessors)
        return result
    instruction = predecessors[0]
    result["predecessor_instruction"] = {
        key: instruction.get(key) for key in
        ("rva", "size", "bytes", "mnemonic", "operands", "groups", "direct_target_rva")
    }
    if instruction["mnemonic"] != "call" or "call" not in instruction.get("groups", []):
        result["callsite_status"] = "RETURN_PREDECESSOR_IS_NOT_CALL"
        return result
    result["callsite_status"] = "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL"
    result["call_kind"] = "direct" if instruction.get("direct_target_rva") is not None else "indirect"
    result["callsite_rva"] = instruction["rva"]
    return result
