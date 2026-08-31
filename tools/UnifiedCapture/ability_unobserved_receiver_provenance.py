"""Trace unobserved Ability dynamic-call endpoints through exact x64 CFG dataflow.

The result is deliberately an endpoint contract, not a guessed method name.
For an IL2CPP virtual call it preserves the receiver provenance and the exact
vtable slot.  For a function pointer loaded from a record it preserves the
record provenance and field offset.  Runtime is requested only when those
mechanical facts remain ambiguous or unknown after the static pass.
"""
from __future__ import annotations

import argparse
from collections import defaultdict, deque
import json
import re
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE
from ability_unobserved_branch_ledger import (
    _resolve_local_jump_tables, _successors as _exact_successors)


GPRS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
VOLATILE = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
ENTRY_ARGUMENTS = {"rcx": 0, "rdx": 1, "r8": 2, "r9": 3}
ALIASES = {
    "rax": {"rax", "eax", "ax", "al", "ah"},
    "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
    "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
    "rdx": {"rdx", "edx", "dx", "dl", "dh"},
    "rsi": {"rsi", "esi", "si", "sil"},
    "rdi": {"rdi", "edi", "di", "dil"},
    "rbp": {"rbp", "ebp", "bp", "bpl"},
    "rsp": {"rsp", "esp", "sp", "spl"},
    **{f"r{i}": {f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b"}
       for i in range(8, 16)},
}
ALIAS_TO_GPR = {alias: register for register, aliases in ALIASES.items()
                for alias in aliases}
MEMORY = re.compile(
    r"^(?:byte|word|dword|qword|xmmword|ymmword) ptr "
    r"\[([a-z0-9]+)(?: ([+-]) (0x[0-9a-f]+|[0-9]+))?\]$")
RIP_MEMORY = re.compile(
    r"^(?:byte|word|dword|qword|xmmword|ymmword) ptr "
    r"\[rip(?: ([+-]) (0x[0-9a-f]+))?\]$")
REGISTER = re.compile(r"^[a-z][a-z0-9]*$")
IMMEDIATE = re.compile(r"^-?(?:0x[0-9a-f]+|[0-9]+)$")
VTABLE_BASE_OFFSET = 0xD0


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    path = path.resolve()
    return {"path": str(path), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _gpr(name: str) -> str | None:
    return ALIAS_TO_GPR.get(name.lower())


def _split_operands(text: str) -> list[str]:
    # Current inputs contain no comma inside a memory expression.  Keep the
    # splitter explicit so a future unsupported form fails closed.
    return [part.strip() for part in text.split(",")]


def _direct_memory(text: str) -> tuple[str, int] | None:
    match = MEMORY.fullmatch(text)
    if not match:
        return None
    base = _gpr(match.group(1))
    if base is None:
        return None
    displacement = int(match.group(3), 0) if match.group(3) else 0
    if match.group(2) == "-":
        displacement = -displacement
    return base, displacement


def _rip_memory(text: str, instruction: dict[str, Any]) -> int | None:
    match = RIP_MEMORY.fullmatch(text)
    if not match:
        return None
    displacement = int(match.group(2), 0) if match.group(2) else 0
    if match.group(1) == "-":
        displacement = -displacement
    return int(instruction["rva"]) + int(instruction["size"]) + displacement


def _json_key(value: dict[str, Any]) -> bytes:
    return canonical(value)


def _dedupe(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_json_key(value): value for value in values}
    return [unique[key] for key in sorted(unique)]


def _structurally_exact(value: dict[str, Any]) -> bool:
    kind = value.get("kind")
    if kind in {"UNKNOWN_WRITER", "IMPLICIT_OR_PARTIAL_WRITE", "CALL_CLOBBER",
                "NO_REACHING_DEFINITION", "UNREACHABLE_POINT",
                "UNSUPPORTED_REGISTER_SOURCE", "UNSUPPORTED_MEMORY_EXPRESSION",
                "UNSUPPORTED_CALL_OPERAND", "LOOP_CYCLE",
                "ENTRY_UNSPECIFIED_REGISTER", "NARROW_OR_PARTIAL_WRITE"}:
        return False
    if kind == "AMBIGUOUS":
        return False
    if kind == "BOUNDED_ALTERNATIVES":
        return all(_structurally_exact(row) for row in value["alternatives"])
    if kind in {"LOAD", "EXACT_FIELD_LOAD", "ADDRESS", "ADDRESS_ADJUST"}:
        return _structurally_exact(value["base"])
    return True


def _entry_stack_delta(value: dict[str, Any]) -> int | None:
    if value.get("kind") == "ENTRY_STACK_POINTER":
        return 0
    if value.get("kind") == "ADDRESS_ADJUST":
        base = _entry_stack_delta(value["base"])
        return None if base is None else base + int(value["delta"])
    if value.get("kind") == "BOUNDED_ALTERNATIVES":
        deltas = {_entry_stack_delta(row) for row in value["alternatives"]}
        return deltas.pop() if len(deltas) == 1 and None not in deltas else None
    return None


def _merge(values: list[dict[str, Any]], *, register: str,
           at_rva: int) -> dict[str, Any]:
    unique = _dedupe(values)
    if len(unique) == 1:
        return unique[0]
    kind = ("BOUNDED_ALTERNATIVES" if all(_structurally_exact(row) for row in unique)
            else "AMBIGUOUS")
    return {"kind": kind, "register": register, "at_rva": at_rva,
            "alternatives": unique}


class ReachingDefinitionAnalyzer:
    """Finite reaching-definition analysis over one exact PDATA body."""

    def __init__(self, instructions: list[dict[str, Any]], begin_rva: int,
                 end_rva: int, this_class: str,
                 fields: dict[tuple[str, int], list[dict[str, Any]]],
                 successors: dict[int, set[int]] | None = None):
        self.instructions = instructions
        self.begin_rva = begin_rva
        self.end_rva = end_rva
        self.this_class = this_class
        self.fields = fields
        self.by_rva = {int(row["rva"]): row for row in instructions}
        self.successors = successors if successors is not None else self._successors()
        self.predecessors: dict[int, set[int]] = defaultdict(set)
        for source, targets in self.successors.items():
            for target in targets:
                self.predecessors[target].add(source)
        self.reachable = self._reachable()
        self.in_defs, self.out_defs = self._solve_reaching_definitions()
        self._origin_cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._origin_active: set[tuple[str, str]] = set()

    def _successors(self) -> dict[int, set[int]]:
        result: dict[int, set[int]] = {}
        for row in self.instructions:
            rva = int(row["rva"])
            following = rva + int(row["size"])
            groups = set(row.get("groups", []))
            mnemonic = str(row["mnemonic"])
            targets: set[int] = set()
            if mnemonic.startswith("ret") or mnemonic in {"ud2", "int3", "hlt"}:
                result[rva] = targets
                continue
            if "jump" in groups:
                target = row.get("direct_target_rva")
                if target is not None and int(target) in self.by_rva:
                    targets.add(int(target))
                if mnemonic != "jmp" and following in self.by_rva:
                    targets.add(following)
            elif following in self.by_rva:
                targets.add(following)
            result[rva] = targets
        return result

    def _reachable(self) -> set[int]:
        reached: set[int] = set()
        queue = [self.begin_rva]
        while queue:
            rva = queue.pop()
            if rva in reached or rva not in self.by_rva:
                continue
            reached.add(rva)
            queue.extend(self.successors[rva] - reached)
        return reached

    @staticmethod
    def _entry_defs() -> dict[str, frozenset[str]]:
        return {register: frozenset({f"entry:{register}"}) for register in GPRS}

    def _written_gprs(self, row: dict[str, Any]) -> set[str]:
        written = {_gpr(name) for name in row.get("regs_write", [])}
        result = {name for name in written if name is not None}
        if "call" in row.get("groups", []):
            # Capstone exposes the architectural call/return stack adjustment
            # as an RSP write.  At the next instruction the Windows x64 ABI
            # stack pointer is back at the same logical value.
            result.discard("rsp")
            result.update(VOLATILE)
        return result

    def _transfer(self, row: dict[str, Any], incoming: dict[str, frozenset[str]]) \
            -> dict[str, frozenset[str]]:
        outgoing = dict(incoming)
        rva = int(row["rva"])
        parts = _split_operands(str(row["operands"]))
        destination = _gpr(parts[0]) if parts else None
        written = self._written_gprs(row)
        for register in written:
            outgoing[register] = frozenset({f"ins:{rva:x}:{register}"})
        # A conditional move retains the old destination on one path.
        if str(row["mnemonic"]).startswith("cmov") and destination:
            outgoing[destination] = frozenset(
                set(incoming.get(destination, frozenset()))
                | {f"ins:{rva:x}:{destination}"})
        return outgoing

    def _solve_reaching_definitions(self) -> tuple[
            dict[int, dict[str, frozenset[str]]],
            dict[int, dict[str, frozenset[str]]]]:
        incoming: dict[int, dict[str, frozenset[str]]] = {}
        outgoing: dict[int, dict[str, frozenset[str]]] = {}
        queue: deque[int] = deque(sorted(self.reachable))
        queued = set(queue)
        while queue:
            rva = queue.popleft()
            queued.discard(rva)
            merged = {register: set() for register in GPRS}
            if rva == self.begin_rva:
                for register, definitions in self._entry_defs().items():
                    merged[register].update(definitions)
            for predecessor in self.predecessors.get(rva, set()):
                if predecessor not in self.reachable or predecessor not in outgoing:
                    continue
                for register, definitions in outgoing[predecessor].items():
                    merged[register].update(definitions)
            next_in = {register: frozenset(definitions)
                       for register, definitions in merged.items()}
            next_out = self._transfer(self.by_rva[rva], next_in)
            if incoming.get(rva) == next_in and outgoing.get(rva) == next_out:
                continue
            incoming[rva] = next_in
            outgoing[rva] = next_out
            for successor in self.successors[rva]:
                if successor in self.reachable and successor not in queued:
                    queue.append(successor)
                    queued.add(successor)
        return incoming, outgoing

    def resolve_before(self, rva: int, register: str) -> dict[str, Any]:
        register = _gpr(register) or register
        if rva not in self.in_defs:
            return {"kind": "UNREACHABLE_POINT", "rva": rva,
                    "register": register}
        definitions = self.in_defs[rva].get(register, frozenset())
        if not definitions:
            return {"kind": "NO_REACHING_DEFINITION", "rva": rva,
                    "register": register}
        origins = [self._origin(definition, register)
                   for definition in sorted(definitions)]
        return _merge(origins, register=register, at_rva=rva)

    def _origin(self, definition: str, register: str) -> dict[str, Any]:
        cache_key = (definition, register)
        if cache_key in self._origin_cache:
            return self._origin_cache[cache_key]
        if cache_key in self._origin_active:
            return {"kind": "LOOP_CYCLE", "definition": definition,
                    "register": register}
        self._origin_active.add(cache_key)
        try:
            if definition.startswith("entry:"):
                result = self._entry_origin(register)
            else:
                _, hex_rva, _ = definition.split(":", 2)
                result = self._instruction_origin(self.by_rva[int(hex_rva, 16)],
                                                  register)
            self._origin_cache[cache_key] = result
            return result
        finally:
            self._origin_active.remove(cache_key)

    def _entry_origin(self, register: str) -> dict[str, Any]:
        if register == "rcx":
            return {"kind": "ENTRY_THIS", "register": register,
                    "class": self.this_class}
        if register in ENTRY_ARGUMENTS:
            return {"kind": "ENTRY_ARGUMENT", "register": register,
                    "ordinal": ENTRY_ARGUMENTS[register]}
        if register == "rsp":
            return {"kind": "ENTRY_STACK_POINTER", "register": register}
        return {"kind": "ENTRY_UNSPECIFIED_REGISTER", "register": register}

    def _resolve_source_register(self, row: dict[str, Any], source: str) -> dict[str, Any]:
        register = _gpr(source)
        if register is None:
            return {"kind": "UNSUPPORTED_REGISTER_SOURCE", "source": source,
                    "writer_rva": int(row["rva"])}
        definitions = self.in_defs[int(row["rva"])].get(register, frozenset())
        origins = [self._origin(definition, register)
                   for definition in sorted(definitions)]
        if not origins:
            return {"kind": "NO_REACHING_DEFINITION", "register": register,
                    "rva": int(row["rva"])}
        return _merge(origins, register=register, at_rva=int(row["rva"]))

    def _memory_origin(self, row: dict[str, Any], operand: str) -> dict[str, Any]:
        rip_rva = _rip_memory(operand, row)
        if rip_rva is not None:
            return {"kind": "RIP_RELATIVE_LOAD", "storage_rva": rip_rva,
                    "writer_rva": int(row["rva"])}
        direct = _direct_memory(operand)
        if direct is None:
            return {"kind": "UNSUPPORTED_MEMORY_EXPRESSION", "operand": operand,
                    "writer_rva": int(row["rva"])}
        base_register, offset = direct
        base = self._resolve_source_register(row, base_register)
        result: dict[str, Any] = {
            "kind": "LOAD", "base": base, "offset": offset,
            "writer_rva": int(row["rva"]), "operand": operand,
        }
        stack_delta = _entry_stack_delta(base)
        if stack_delta is not None:
            result.update(kind="ENTRY_STACK_LOAD",
                          stack_entry_offset=stack_delta + offset)
        base_class = base.get("class")
        candidates = self.fields.get((str(base_class), offset), []) if base_class else []
        if len(candidates) == 1:
            field = candidates[0]
            result.update({"kind": "EXACT_FIELD_LOAD", "field": field,
                           "class": field.get("materializedClass")})
        return result

    def _instruction_origin(self, row: dict[str, Any], register: str) -> dict[str, Any]:
        rva = int(row["rva"])
        mnemonic = str(row["mnemonic"])
        parts = _split_operands(str(row["operands"]))
        destination = _gpr(parts[0]) if parts else None
        if "call" in row.get("groups", []):
            if register == "rax":
                return {"kind": "CALL_RETURN", "callsite_rva": rva,
                        "direct_target_rva": row.get("direct_target_rva"),
                        "operands": row["operands"]}
            return {"kind": "CALL_CLOBBER", "callsite_rva": rva,
                    "register": register}
        if register == "rsp" and mnemonic in {"push", "pop"}:
            return {"kind": "ADDRESS_ADJUST",
                    "base": self._resolve_source_register(row, "rsp"),
                    "delta": -8 if mnemonic == "push" else 8,
                    "writer_rva": rva}
        if destination != register:
            return {"kind": "IMPLICIT_OR_PARTIAL_WRITE", "writer_rva": rva,
                    "register": register, "mnemonic": mnemonic,
                    "operands": row["operands"]}
        if parts and parts[0] != register:
            if mnemonic == "xor" and len(parts) == 2 and _gpr(parts[0]) == _gpr(parts[1]):
                return {"kind": "CONSTANT", "value": 0, "writer_rva": rva,
                        "written_width_register": parts[0]}
            if mnemonic == "mov" and len(parts) == 2 and IMMEDIATE.fullmatch(parts[1]):
                return {"kind": "CONSTANT", "value": int(parts[1], 0),
                        "writer_rva": rva, "written_width_register": parts[0]}
            return {"kind": "NARROW_OR_PARTIAL_WRITE", "writer_rva": rva,
                    "register": register, "written_register": parts[0],
                    "mnemonic": mnemonic, "operands": row["operands"]}
        if mnemonic == "mov" and len(parts) == 2:
            source = parts[1]
            if _gpr(source):
                return self._resolve_source_register(row, source)
            if _direct_memory(source) or RIP_MEMORY.fullmatch(source):
                return self._memory_origin(row, source)
            if IMMEDIATE.fullmatch(source):
                return {"kind": "CONSTANT", "value": int(source, 0),
                        "writer_rva": rva}
        if mnemonic == "lea" and len(parts) == 2:
            direct = _direct_memory("qword ptr " + parts[1])
            if direct:
                base_register, offset = direct
                return {"kind": "ADDRESS", "base": self._resolve_source_register(
                            row, base_register), "offset": offset,
                        "writer_rva": rva}
            rip_rva = _rip_memory("qword ptr " + parts[1], row)
            if rip_rva is not None:
                return {"kind": "RIP_RELATIVE_ADDRESS", "storage_rva": rip_rva,
                        "writer_rva": rva}
        if mnemonic == "xor" and len(parts) == 2 and _gpr(parts[0]) == _gpr(parts[1]):
            return {"kind": "CONSTANT", "value": 0, "writer_rva": rva}
        if mnemonic in {"add", "sub"} and len(parts) == 2 and IMMEDIATE.fullmatch(parts[1]):
            delta = int(parts[1], 0) * (1 if mnemonic == "add" else -1)
            return {"kind": "ADDRESS_ADJUST", "base": self._resolve_source_register(
                        row, parts[0]), "delta": delta, "writer_rva": rva}
        if mnemonic.startswith("cmov") and len(parts) == 2:
            return self._resolve_source_register(row, parts[1])
        return {"kind": "UNKNOWN_WRITER", "writer_rva": rva,
                "register": register, "mnemonic": mnemonic,
                "operands": row["operands"]}


def _is_exact_provenance(origin: dict[str, Any]) -> bool:
    return _structurally_exact(origin)


def _vtable_contract(target: dict[str, Any]) -> dict[str, Any] | None:
    if target.get("kind") not in {"LOAD", "EXACT_FIELD_LOAD"}:
        return None
    vtable_offset = int(target["offset"])
    class_load = target.get("base", {})
    if (class_load.get("kind") not in {"LOAD", "EXACT_FIELD_LOAD"}
            or int(class_load.get("offset", -1)) != 0):
        return None
    if vtable_offset < VTABLE_BASE_OFFSET or (vtable_offset - VTABLE_BASE_OFFSET) % 8:
        return None
    receiver = class_load["base"]
    return {
        "kind": "IL2CPP_VTABLE_SLOT_ENDPOINT",
        "audited_vtable_base_offset": VTABLE_BASE_OFFSET,
        "vtable_entry_offset": vtable_offset,
        "vtable_slot": (vtable_offset - VTABLE_BASE_OFFSET) // 8,
        "receiver_provenance": receiver,
        "receiver_provenance_exact": _is_exact_provenance(receiver),
        "concrete_runtime_class_proven": bool(receiver.get("class")),
    }


def _target_origin(analyzer: ReachingDefinitionAnalyzer,
                   callsite: dict[str, Any]) -> dict[str, Any]:
    parts = _split_operands(str(callsite["operands"]))
    if len(parts) != 1:
        return {"kind": "UNSUPPORTED_CALL_OPERAND", "operands": callsite["operands"]}
    operand = parts[0]
    register = _gpr(operand)
    if register:
        return analyzer.resolve_before(int(callsite["rva"]), register)
    direct = _direct_memory(operand)
    if direct:
        base_register, offset = direct
        return {"kind": "LOAD", "base": analyzer.resolve_before(
                    int(callsite["rva"]), base_register), "offset": offset,
                "writer_rva": int(callsite["rva"]), "operand": operand}
    return {"kind": "UNSUPPORTED_CALL_OPERAND", "operands": callsite["operands"]}


def _field_index(coverage: dict[str, Any]) \
        -> dict[tuple[str, int], list[dict[str, Any]]]:
    fields: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for type_row in coverage["types"]:
        for field in type_row.get("executor_fields", []) + type_row.get("config_fields", []):
            candidate = {key: field.get(key) for key in (
                "class", "field", "materializedClass", "offset", "token")}
            key = (str(field["class"]), int(field["offset"], 0))
            if candidate not in fields.setdefault(key, []):
                fields[key].append(candidate)
    return fields


def build(dynamic_runtime_path: Path, base_identity_path: Path,
          coverage_path: Path, game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    runtime = _load(dynamic_runtime_path)
    base_identity = _load(base_identity_path)
    coverage = _load(coverage_path)
    if runtime.get("schema") != "uc.ability-dynamic-dispatch-runtime-analysis.v1":
        raise ValueError("unsupported dynamic runtime analysis")
    if base_identity.get("schema") != "uc.ability-unobserved-base-identity-join.v1":
        raise ValueError("unsupported base identity join")
    if coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported coverage ledger")
    base_by_point = {row["point"]: row for row in base_identity["sites"]}
    fields = _field_index(coverage)
    image = NativePE(game_path)
    rows = []
    for site in runtime["dynamic_sites"]:
        if site.get("observation") == "OBSERVED":
            continue
        represented = site["static_contract"]["represented_callsites"]
        if not isinstance(represented, list):
            represented = [represented]
        for callsite_contract in represented:
            if callsite_contract["caller_method"] == ".cctor":
                continue
            point = site["point"]
            base = base_by_point.get(point)
            if base is None:
                raise ValueError(f"missing base identity for {point}")
            callsite_rva = int(callsite_contract["site_rva"])
            function = image.containing(callsite_rva)
            if function is None:
                raise ValueError(f"callsite lacks PDATA owner: {callsite_rva:#x}")
            decoded = image.decode(function)
            if not decoded["all_declared_bytes_decoded"]:
                raise ValueError(f"callsite body is not completely decoded: {callsite_rva:#x}")
            callsite = next((row for row in decoded["instructions"]
                             if int(row["rva"]) == callsite_rva), None)
            if callsite is None or "call" not in callsite.get("groups", []):
                raise ValueError(f"contract does not point to a decoded call: {callsite_rva:#x}")
            analyzer = ReachingDefinitionAnalyzer(
                decoded["instructions"], function.begin, function.end,
                str(base["method_this_class"]), fields,
                _exact_successors(
                    decoded["instructions"], function.begin, function.end,
                    _resolve_local_jump_tables(
                        image, decoded["instructions"], function.begin, function.end)))
            target = _target_origin(analyzer, callsite)
            endpoint = _vtable_contract(target)
            if endpoint is None:
                endpoint = {
                    "kind": "FUNCTION_POINTER_ENDPOINT",
                    "target_provenance": target,
                    "target_provenance_exact": _is_exact_provenance(target),
                }
                if target.get("kind") in {"LOAD", "EXACT_FIELD_LOAD"}:
                    endpoint["record_provenance"] = target.get("base")
                    endpoint["record_field_offset"] = target.get("offset")
            closed = bool(endpoint.get("receiver_provenance_exact",
                                       endpoint.get("target_provenance_exact", False)))
            rows.append({
                "point": point,
                "caller_type": callsite_contract["caller_type"],
                "caller_method": callsite_contract["caller_method"],
                "method_this_class": base["method_this_class"],
                "pdata_begin_rva": function.begin,
                "pdata_end_rva": function.end,
                "callsite_rva": callsite_rva,
                "call_operands": callsite["operands"],
                "previous_local_classification": callsite_contract.get("local_dataflow", {}).get("status"),
                "endpoint_contract": endpoint,
                "static_endpoint_contract_closed": closed,
                "runtime_required": not closed,
                "human_readable_callee_name_assigned": False,
            })
    expected = 14
    if len(rows) != expected:
        raise ValueError(f"expected {expected} non-cctor unobserved callsites, got {len(rows)}")
    summary = {
        "in_scope_unobserved_callsites": len(rows),
        "il2cpp_vtable_slot_endpoints": sum(
            row["endpoint_contract"]["kind"] == "IL2CPP_VTABLE_SLOT_ENDPOINT"
            for row in rows),
        "function_pointer_endpoints": sum(
            row["endpoint_contract"]["kind"] == "FUNCTION_POINTER_ENDPOINT"
            for row in rows),
        "static_endpoint_contracts_closed": sum(
            row["static_endpoint_contract_closed"] for row in rows),
        "runtime_endpoint_gaps": sum(row["runtime_required"] for row in rows),
        "reclassified_previous_register_target_as_vtable": sum(
            row["previous_local_classification"] == "REGISTER_TARGET_LOADED_FROM_RECORD_FIELD"
            and row["endpoint_contract"]["kind"] == "IL2CPP_VTABLE_SLOT_ENDPOINT"
            for row in rows),
    }
    artifact = {
        "schema": "uc.ability-unobserved-receiver-provenance.v1",
        "sources": {
            "dynamic_runtime": _source(dynamic_runtime_path),
            "base_identity": _source(base_identity_path),
            "ability_coverage": _source(coverage_path),
            "game_module": _source(game_path),
        },
        "summary": summary,
        "acceptance_rules": [
            "a virtual endpoint closes statically when the exact callsite, IL2CPP vtable slot and receiver provenance are mechanically bounded",
            "a concrete runtime class or human-readable callee name is not invented when the receiver is an argument, call return or other intentionally dynamic source",
            "a register-indirect call is independently reclassified as a vtable call when its exact reaching definition is object->class load followed by the audited class-vtable offset",
            "an endpoint remains runtime-blocking only when its receiver or target provenance contains an unknown or ambiguous reaching definition",
        ],
        "runtime_required_now": summary["runtime_endpoint_gaps"] > 0,
        "sites": sorted(rows, key=lambda row: row["callsite_rva"]),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-unobserved-receiver-provenance.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-unobserved-receiver-provenance-report.v1",
        "artifact": _source(artifact_path),
        "summary": summary,
        "runtime_required_now": artifact["runtime_required_now"],
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dynamic-runtime", type=Path, required=True)
    parser.add_argument("--base-identity", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.dynamic_runtime.resolve(), args.base_identity.resolve(),
                     args.coverage.resolve(), args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_receiver_provenance", error, {
            "dynamic_runtime": str(args.dynamic_runtime),
            "base_identity": str(args.base_identity),
            "coverage": str(args.coverage), "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
