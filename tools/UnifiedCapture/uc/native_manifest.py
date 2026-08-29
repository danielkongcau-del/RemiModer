from __future__ import annotations

import bisect
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

EXIT_SCHEMA = "uc.native-exit-manifest.v1"
CALLSITE_SCHEMA = "uc.native-callsite-manifest.v1"
ROLES = {"primary", "cold_fragment", "eh_funclet", "thunk", "unknown"}
TERMINALS = {"normal_return", "funclet_return", "tail_transfer", "terminal_branch", "terminal_trap", "unresolved"}
NONVOLATILE = {"rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"}
RAX_ALIASES = {"rax", "eax", "ax", "al", "ah"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class RuntimeFunction:
    begin: int
    end: int
    unwind_rva: int


class NativePE:
    """Minimal read-only PE32+ and x64 exception-directory reader.

    It intentionally emits mechanical candidates. It does not turn a linear
    decode or a .pdata record into a logical-function or normal-exit claim.
    """

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.data = self.path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"not a PE image: {self.path}")
        section_count = struct.unpack_from("<H", self.data, pe + 6)[0]
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        optional = pe + 24
        if struct.unpack_from("<H", self.data, optional)[0] != 0x20B:
            raise ValueError("only PE32+ is supported")
        self.image_base = struct.unpack_from("<Q", self.data, optional + 24)[0]
        self.size_of_image = struct.unpack_from("<I", self.data, optional + 56)[0]
        self.sections = []
        for index in range(section_count):
            pos = optional + optional_size + index * 40
            virtual_size, va, raw_size, raw_pointer = struct.unpack_from("<IIII", self.data, pos + 8)
            flags = struct.unpack_from("<I", self.data, pos + 36)[0]
            self.sections.append({
                "name": self.data[pos:pos + 8].rstrip(b"\0").decode("ascii", "replace"),
                "rva": va,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
                "flags": flags,
            })
        exception_rva, exception_size = struct.unpack_from("<II", self.data, optional + 112 + 3 * 8)
        table = self.offset(exception_rva)
        records = []
        for index in range(exception_size // 12):
            begin, end, unwind = struct.unpack_from("<III", self.data, table + index * 12)
            if begin < end:
                records.append(RuntimeFunction(begin, end, unwind))
        self.runtime_functions = tuple(sorted(records, key=lambda row: (row.begin, row.end, row.unwind_rva)))
        self.starts = tuple(row.begin for row in self.runtime_functions)
        self.by_start = {row.begin: row for row in self.runtime_functions}
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self._decode_cache = {}

    def offset(self, rva: int) -> int:
        for section in self.sections:
            if section["rva"] <= rva < section["rva"] + section["raw_size"]:
                return section["raw_pointer"] + rva - section["rva"]
        raise ValueError(f"RVA not backed by file bytes: {rva:#x}")

    def bytes_at(self, rva: int, size: int) -> bytes:
        offset = self.offset(rva)
        raw = self.data[offset:offset + size]
        if len(raw) != size:
            raise ValueError(f"short file-backed range at {rva:#x}")
        return raw

    def containing(self, rva: int) -> RuntimeFunction | None:
        index = bisect.bisect_right(self.starts, rva) - 1
        if index >= 0:
            row = self.runtime_functions[index]
            if rva < row.end:
                return row
        return None

    def unwind(self, row: RuntimeFunction) -> dict:
        pos = self.offset(row.unwind_rva)
        version_flags, prolog_size, code_count, frame = struct.unpack_from("<BBBB", self.data, pos)
        version = version_flags & 0x7
        flags = version_flags >> 3
        tail = pos + 4 + ((code_count + 1) & ~1) * 2
        result = {
            "version": version,
            "flags": flags,
            "prolog_size": prolog_size,
            "unwind_code_slots": code_count,
            "frame_register": frame & 0xF,
            "frame_offset": frame >> 4,
            "has_exception_handler": bool(flags & 0x1),
            "has_unwind_handler": bool(flags & 0x2),
            "has_chain_info": bool(flags & 0x4),
            "handler_rva": None,
            "chained_runtime_function": None,
        }
        if flags & 0x4:
            begin, end, unwind = struct.unpack_from("<III", self.data, tail)
            result["chained_runtime_function"] = {"begin_rva": begin, "end_rva": end, "unwind_rva": unwind}
        elif flags & 0x3:
            result["handler_rva"] = struct.unpack_from("<I", self.data, tail)[0]
        return result

    def decode(self, row: RuntimeFunction) -> dict:
        cached = self._decode_cache.get(row.begin)
        if cached is not None:
            return cached
        raw = self.bytes_at(row.begin, row.end - row.begin)
        instructions = []
        cursor = row.begin
        for ins in self.cs.disasm(raw, self.image_base + row.begin):
            rva = ins.address - self.image_base
            if rva != cursor:
                break
            reads, writes = ins.regs_access()
            direct_target = None
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                direct_target = int(ins.operands[0].imm - self.image_base)
            instructions.append({
                "rva": rva,
                "size": ins.size,
                "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic,
                "operands": ins.op_str,
                "groups": [ins.group_name(group) for group in ins.groups],
                "regs_read": [ins.reg_name(reg) for reg in reads],
                "regs_write": [ins.reg_name(reg) for reg in writes],
                "direct_target_rva": direct_target,
            })
            cursor += ins.size
        result = {"instructions": instructions, "all_declared_bytes_decoded": cursor == row.end}
        self._decode_cache[row.begin] = result
        return result

    def cfg(self, row: RuntimeFunction) -> dict:
        decoded = self.decode(row)
        by_rva = {ins["rva"]: ins for ins in decoded["instructions"]}
        position = {ins["rva"]: index for index, ins in enumerate(decoded["instructions"])}
        reachable = set()
        edges = []
        terminals = []
        resolved_indirect = []
        queue = [row.begin]
        queued = {row.begin}
        while queue:
            cursor = queue.pop()
            while cursor in by_rva and cursor not in reachable:
                ins = by_rva[cursor]
                reachable.add(cursor)
                following = cursor + ins["size"]
                groups = set(ins["groups"])
                mnemonic = ins["mnemonic"]
                target = ins["direct_target_rva"]
                if mnemonic.startswith("ret"):
                    terminals.append({"rva": cursor, "terminal_semantics": "normal_return", "mechanical_only": True})
                    break
                if mnemonic in ("ud2", "int3", "hlt"):
                    terminals.append({"rva": cursor, "terminal_semantics": "unresolved", "mechanical_only": True})
                    break
                if "jump" in groups:
                    conditional = mnemonic != "jmp"
                    if target is None:
                        switch_targets = self._relative_jump_table(decoded["instructions"], position[cursor], row)
                        if switch_targets:
                            for switch_target in switch_targets:
                                edges.append({"from_rva": cursor, "to_rva": switch_target, "kind": "resolved-jump-table"})
                                if switch_target not in queued:
                                    queue.append(switch_target)
                                    queued.add(switch_target)
                            resolved_indirect.append({"site_rva": cursor, "target_rvas": switch_targets,
                                                      "evidence": "bounded-rip-relative-signed-dword-table"})
                        else:
                            terminals.append({"rva": cursor, "terminal_semantics": "unresolved", "mechanical_only": True,
                                              "reason": "indirect-branch"})
                    elif row.begin <= target < row.end:
                        edges.append({"from_rva": cursor, "to_rva": target, "kind": "branch"})
                        if target not in queued:
                            queue.append(target)
                            queued.add(target)
                    else:
                        terminals.append({"rva": cursor, "target_rva": target,
                                          "terminal_semantics": "terminal_branch", "mechanical_only": True})
                    if conditional:
                        edges.append({"from_rva": cursor, "to_rva": following, "kind": "fallthrough"})
                        cursor = following
                        continue
                    break
                if "call" in groups:
                    edges.append({"from_rva": cursor, "to_rva": following, "kind": "fallthrough-after-call"})
                cursor = following
            else:
                if cursor == row.end:
                    terminals.append({"rva": row.end, "target_rva": row.end,
                                      "terminal_semantics": "terminal_branch", "mechanical_only": True,
                                      "reason": "runtime-range-fallthrough"})
        unique_terminals = {}
        for terminal in terminals:
            key = (terminal["rva"], terminal.get("target_rva"), terminal.get("reason"))
            unique_terminals[key] = terminal
        return {
            "reachable_instruction_rvas": sorted(reachable),
            "edges": edges,
            "terminals": sorted(unique_terminals.values(), key=lambda item: (item["rva"], item.get("target_rva", -1))),
            "resolved_indirect_branches": resolved_indirect,
            "decode_complete": decoded["all_declared_bytes_decoded"],
        }

    def _relative_jump_table(self, instructions: list[dict], index: int, row: RuntimeFunction) -> list[int] | None:
        terminal = instructions[index]
        match = re.fullmatch(r"jmp ([a-z0-9]+)", terminal["mnemonic"] + " " + terminal["operands"])
        if not match:
            return None
        target_reg = match.group(1)
        base_reg = None
        index_reg = None
        table_rva = None
        maximum = None
        for ins in reversed(instructions[max(0, index - 16):index]):
            operands = ins["operands"].replace(" ", "")
            add = re.fullmatch(rf"{target_reg},([a-z0-9]+)", operands) if ins["mnemonic"] == "add" else None
            if add and base_reg is None:
                base_reg = add.group(1)
                continue
            if base_reg and ins["mnemonic"] == "movsxd":
                load = re.fullmatch(rf"{target_reg},dwordptr\[{base_reg}\+([a-z0-9]+)\*4\]", operands)
                if load:
                    index_reg = load.group(1)
                    continue
            if base_reg and ins["mnemonic"] == "lea":
                lea = re.fullmatch(rf"{base_reg},\[rip([+-])0x([0-9a-f]+)\]", operands)
                if lea:
                    displacement = int(lea.group(2), 16) * (1 if lea.group(1) == "+" else -1)
                    table_rva = ins["rva"] + ins["size"] + displacement
                    continue
            if index_reg and ins["mnemonic"] == "cmp":
                compare = re.fullmatch(r"([a-z0-9]+),(0x[0-9a-f]+|[0-9]+)", operands)
                if compare and (compare.group(1) == index_reg or compare.group(1).endswith("l")):
                    maximum = int(compare.group(2), 0)
                    break
        if base_reg is None or index_reg is None or table_rva is None or maximum is None or maximum > 1024:
            return None
        try:
            offsets = struct.unpack("<" + "i" * (maximum + 1), self.bytes_at(table_rva, (maximum + 1) * 4))
        except (ValueError, struct.error):
            return None
        targets = [table_rva + offset for offset in offsets]
        boundaries = {ins["rva"] for ins in instructions}
        if not all(row.begin <= target < row.end and target in boundaries for target in targets):
            return None
        return targets

    def direct_xrefs(self, target_rvas: set[int]) -> list[dict]:
        rows = []
        for section in self.sections:
            if not section["flags"] & 0x20000000:
                continue
            raw = self.data[section["raw_pointer"]:section["raw_pointer"] + section["raw_size"]]
            for opcode in (0xE8, 0xE9):
                start = 0
                marker = bytes((opcode,))
                while True:
                    pos = raw.find(marker, start)
                    if pos < 0:
                        break
                    start = pos + 1
                    if pos + 5 > len(raw):
                        continue
                    site = section["rva"] + pos
                    target = site + 5 + struct.unpack_from("<i", raw, pos + 1)[0]
                    if target not in target_rvas:
                        continue
                    owner = self.containing(site)
                    if owner is None:
                        continue
                    instruction = next((ins for ins in self.decode(owner)["instructions"] if ins["rva"] == site), None)
                    valid = bool(instruction and instruction["mnemonic"] in ("call", "jmp") and
                                 instruction["direct_target_rva"] == target and instruction["size"] == 5)
                    if valid:
                        rows.append({
                            "site_rva": site,
                            "target_rva": target,
                            "owner_runtime_function_rva": owner.begin,
                            "kind": instruction["mnemonic"],
                            "bytes": instruction["bytes"],
                            "instruction_boundary_verified_by": "capstone",
                        })
        return sorted(rows, key=lambda item: (item["target_rva"], item["site_rva"]))

    def direct_control_xrefs(self, target_rvas: set[int]) -> list[dict]:
        """Scan all file-backed executable bytes, then require a pdata/Capstone boundary."""
        rows = []
        pattern = re.compile(b"[\xe8\xe9\xeb\x70-\x7f\xe0-\xe3]|\x0f[\x80-\x8f]")
        for section in self.sections:
            if not section["flags"] & 0x20000000:
                continue
            raw = self.data[section["raw_pointer"]:section["raw_pointer"] + section["raw_size"]]
            for match in pattern.finditer(raw):
                pos = match.start()
                opcode = raw[pos]
                if opcode in (0xE8, 0xE9):
                    size, displacement_size = 5, 4
                elif opcode == 0x0F:
                    size, displacement_size = 6, 4
                else:
                    size, displacement_size = 2, 1
                if pos + size > len(raw):
                    continue
                displacement_offset = pos + size - displacement_size
                displacement = int.from_bytes(raw[displacement_offset:displacement_offset + displacement_size],
                                              "little", signed=True)
                site = section["rva"] + pos
                target = site + size + displacement
                if target not in target_rvas:
                    continue
                owner = self.containing(site)
                if owner is None:
                    continue
                instruction = next((ins for ins in self.decode(owner)["instructions"] if ins["rva"] == site), None)
                if not instruction or instruction["size"] != size or instruction["direct_target_rva"] != target:
                    continue
                if not ({"jump", "call"} & set(instruction["groups"])):
                    continue
                rows.append({
                    "site_rva": site,
                    "target_rva": target,
                    "owner_runtime_function_rva": owner.begin,
                    "mnemonic": instruction["mnemonic"],
                    "bytes": instruction["bytes"],
                    "instruction_boundary_verified_by": "capstone",
                })
        return sorted(rows, key=lambda item: (item["target_rva"], item["site_rva"]))


def _pure_epilogue_instruction(ins: dict) -> bool:
    mnemonic = ins["mnemonic"]
    operands = ins["operands"].replace(" ", "")
    if mnemonic.startswith("ret") or mnemonic in ("nop", "vzeroupper"):
        return True
    if mnemonic == "pop" and operands in NONVOLATILE:
        return True
    if mnemonic == "add" and operands.startswith("rsp,0x"):
        return True
    if mnemonic == "lea" and operands.startswith("rsp,["):
        return True
    if mnemonic == "mov" and operands.startswith("rsp,"):
        return True
    if mnemonic == "leave":
        return True
    return False


def _stack_effect(ins: dict) -> int | None:
    mnemonic = ins["mnemonic"]
    operands = ins["operands"].replace(" ", "")
    if mnemonic == "pop":
        return 8
    if mnemonic == "add" and operands.startswith("rsp,0x"):
        return int(operands.split(",", 1)[1], 16)
    if mnemonic in ("nop", "vzeroupper"):
        return 0
    if mnemonic.startswith("ret"):
        return 0
    return None


def looks_like_x64_tail_transfer(pe: NativePE, row: RuntimeFunction, terminal_rva: int) -> bool:
    instructions = pe.decode(row)["instructions"]
    index = next((pos for pos, ins in enumerate(instructions) if ins["rva"] == terminal_rva), None)
    if index is None:
        return False
    terminal = instructions[index]
    if terminal["mnemonic"] != "jmp" or terminal["rva"] + terminal["size"] != row.end:
        return False
    saw_stack_restore = False
    cursor = index - 1
    while cursor >= 0:
        ins = instructions[cursor]
        operands = ins["operands"].replace(" ", "")
        if ins["mnemonic"] == "pop" and ins["operands"].strip() in NONVOLATILE:
            saw_stack_restore = True
        elif ins["mnemonic"] == "add" and operands.startswith("rsp,0x"):
            saw_stack_restore = True
        elif ins["mnemonic"] == "lea" and operands.startswith("rsp,["):
            saw_stack_restore = True
        elif ins["mnemonic"] == "mov" and any(operands.startswith(reg + ",qwordptr[rsp") for reg in NONVOLATILE):
            pass
        elif ins["mnemonic"] in ("nop", "vzeroupper"):
            pass
        else:
            break
        cursor -= 1
    return saw_stack_restore


def exit_probe_candidates(pe: NativePE, row: RuntimeFunction, cfg: dict) -> list[dict]:
    decoded = pe.decode(row)["instructions"]
    index = {ins["rva"]: pos for pos, ins in enumerate(decoded)}
    result = []
    for terminal in cfg["terminals"]:
        if terminal["terminal_semantics"] != "normal_return":
            continue
        ret_rva = terminal["rva"]
        pos = index[ret_rva]
        sequence = [decoded[pos]]
        cursor = pos - 1
        while cursor >= 0:
            prior = decoded[cursor]
            if prior["rva"] + prior["size"] != sequence[0]["rva"] or not _pure_epilogue_instruction(prior):
                break
            sequence.insert(0, prior)
            cursor -= 1
        sites = []
        for required in (5, 16):
            accumulated = 0
            chosen = None
            for ins in reversed(sequence):
                accumulated += ins["size"]
                if accumulated >= required:
                    chosen = ins
                    break
            if chosen is None:
                continue
            selected = [ins for ins in sequence if ins["rva"] >= chosen["rva"]]
            span = ret_rva + decoded[pos]["size"] - chosen["rva"]
            writes = {reg for ins in selected for reg in ins["regs_write"]}
            effects = [_stack_effect(ins) for ins in selected[:-1]]
            stack_adjust = sum(effects) if all(effect is not None for effect in effects) else None
            restores = [ins["operands"].strip() for ins in selected[:-1]
                        if ins["mnemonic"] == "pop" and ins["operands"].strip() in NONVOLATILE]
            sites.append({
                "candidate_for_minimum_span": required,
                "probe_rva": chosen["rva"],
                "ret_rva": ret_rva,
                "available_span_through_ret": span,
                "expected_bytes": pe.bytes_at(chosen["rva"], span).hex(),
                "instruction_rvas": [ins["rva"] for ins in selected],
                "backend_patch_contract": None,
                "incoming_edges_complete": False,
                "exit_capture_contract": {
                    "probe_semantics": "pre_instruction",
                    "return_value_stable": not bool(writes & RAX_ALIASES),
                    "xmm_return_stable": "xmm0" not in writes,
                    "stack_restored": stack_adjust == 0,
                    "caller_return_slot_valid": stack_adjust == 0,
                    "stack_adjust_remaining": stack_adjust,
                    "nonvolatile_restore_remaining": restores,
                    "relocation_class": "pure_epilogue",
                    "exception_neutral_relocation": None,
                    "contract_evidence": ["capstone-instruction-effects", "mechanical-epilogue-simulation"],
                },
            })
        result.append({
            "exit_site_id": f"ret-{ret_rva:x}",
            "runtime_function_begin_rva": row.begin,
            "ret_rva": ret_rva,
            "terminal_semantics": "normal_return",
            "terminal_semantics_verified": False,
            "probe_candidates": sites,
        })
    return result


def validate_exit_manifest(value: dict) -> dict:
    if value.get("schema") != EXIT_SCHEMA:
        raise ValueError("unsupported exit manifest schema")
    if value.get("status") not in ("mechanical-candidate", "partially-verified", "three-way-verified"):
        raise ValueError("invalid exit manifest status")
    seen = set()
    for function in value.get("functions", []):
        identity = (function["module"], function["entry_rva"], function["function_id"])
        if identity in seen:
            raise ValueError("duplicate function identity")
        seen.add(identity)
        for runtime in function["runtime_functions"]:
            if runtime["runtime_function_role"] not in ROLES:
                raise ValueError("invalid runtime function role")
        for exit_site in function["normal_exits"]:
            if exit_site["terminal_semantics"] not in TERMINALS:
                raise ValueError("invalid terminal semantics")
            for candidate in exit_site["probe_candidates"]:
                contract = candidate["exit_capture_contract"]
                required = {"probe_semantics", "return_value_stable", "xmm_return_stable", "stack_restored",
                            "caller_return_slot_valid", "stack_adjust_remaining", "nonvolatile_restore_remaining",
                            "relocation_class", "exception_neutral_relocation", "contract_evidence"}
                if set(contract) != required or contract["probe_semantics"] != "pre_instruction":
                    raise ValueError("incomplete exit capture contract")
                if candidate["backend_patch_contract"] is not None and value["status"] == "mechanical-candidate":
                    raise ValueError("mechanical manifest cannot claim a backend patch contract")
        completeness = function["completeness"]
        if value["status"] == "mechanical-candidate" and any(completeness.values()):
            raise ValueError("mechanical candidate cannot claim complete exit sets")
    return {"functions": len(seen), "status": value["status"]}


def validate_callsite_manifest(value: dict) -> dict:
    if value.get("schema") != CALLSITE_SCHEMA:
        raise ValueError("unsupported callsite manifest schema")
    contract = value.get("runtime_resolution_contract", {})
    if contract.get("entry_rsp_source") != "target-pre-instruction-cpu-context":
        raise ValueError("callsite contract must use target architectural RSP")
    if not contract.get("fixed_subtract_forbidden") or not contract.get("tail_calls_need_terminal_branch_evidence"):
        raise ValueError("unsafe callsite inference contract")
    return {"targets": len(value.get("targets", [])), "status": value.get("status")}
