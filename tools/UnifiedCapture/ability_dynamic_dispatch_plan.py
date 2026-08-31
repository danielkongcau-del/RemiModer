"""Prepare one bounded runtime unit for unresolved Ability dispatch identity.

The generated source plan never assigns semantic callee names.  It snapshots
the still-unresolved initialized slots at one low-frequency Behavior load
entry and observes only the object/vtable or register dispatch callsites that
cannot be resolved from preserved native metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE
from uc.site_qualification import validate_site_qualification


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_INDIRECT = (ROOT / "extracted/analysis/ability-executor-indirect-call-join-"
                    "20260831-v9/ability-executor-indirect-call-join.json")
DEFAULT_LAYOUT = ROOT / "extracted/analysis/class-layout.md"
DEFAULT_LEDGER = (ROOT / "extracted/analysis/controller-closure-ledger-20260831-v37/"
                  "controller-closure-state.json")
DEFAULT_GAME = ROOT / "miHoYo Launcher/games/ZenlessZoneZero Game/GameAssembly.dll"
ANCHOR_RVA = 0x1E45EEF0


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _reg(rid: str, register: str, evidence: list[str], width: int = 8) -> dict[str, Any]:
    return {"id": rid, "base": register, "op": "register", "width": width,
            "phase": "enter", "evidence": evidence}


def _scalar(rid: str, base: str, offset: int, evidence: list[str],
            width: int = 8) -> dict[str, Any]:
    return {"id": rid, "base": base, "offset": offset, "op": "scalar",
            "width": width, "phase": "enter", "evidence": evidence}


def _cstring(rid: str, base: str, evidence: list[str], maximum: int = 128) -> dict[str, Any]:
    return {"id": rid, "base": base, "op": "string", "max_bytes": maximum,
            "phase": "enter", "evidence": evidence}


def _instruction_window(image: NativePE, rva: int) -> tuple[bytes, int, list[dict[str, Any]]]:
    prefix = image.bytes_at(rva, 32)
    span = 0
    instructions = []
    for instruction in image.cs.disasm(prefix, image.image_base + rva):
        row = {"rva": instruction.address - image.image_base,
               "size": instruction.size, "mnemonic": instruction.mnemonic,
               "operands": instruction.op_str, "bytes": instruction.bytes.hex()}
        instructions.append(row)
        span += instruction.size
        if span >= 16:
            break
    if span < 16:
        raise ValueError(f"{rva:#x}: no whole-instruction relocation window of at least 16 bytes")
    return prefix, span, instructions


def _dynamic_reads(rows: list[dict[str, Any]], evidence: list[str],
                   probe_rva: int) -> list[dict[str, Any]]:
    reads: list[dict[str, Any]] = []
    ids: set[str] = set()

    def add(row: dict[str, Any]) -> None:
        if row["id"] not in ids:
            ids.add(row["id"])
            reads.append(row)

    for index, row in enumerate(rows):
        flow = row["local_dataflow"]
        suffix = f"{index}-{row['site_rva']:x}"
        if int(row["site_rva"]) == 0x147FA574 and probe_rva == 0x147FA56F:
            # Both native lookup paths converge here with the resolved call
            # target in R8.  RAX is no longer the class on the inlined path,
            # so preserve only the raw receiver/target and the two stack
            # result slots instead of manufacturing a class identity.
            add(_reg(f"dispatch-target-{suffix}", "r8", evidence))
            add(_reg("dispatch-receiver-rbx", "rbx", evidence))
            add(_scalar("resolved-target-stack", "rsp", 0x50, evidence))
            add(_scalar("resolved-method-metadata-stack", "rsp", 0x58, evidence))
            continue
        if int(row["site_rva"]) == 0x12CF2355 and probe_rva == 0x12CF2338:
            add(_reg("attach-owner-root-rcx", "rcx", evidence))
            add(_scalar("attach-owner", "attach-owner-root-rcx", 0x68, evidence))
            add(_scalar("attach-dispatch-record", "attach-owner", 0x10, evidence))
            add(_scalar(f"dispatch-target-{suffix}", "attach-dispatch-record", 8, evidence))
            continue
        if row["dispatch_form"] == "OBJECT_OR_VTABLE_SLOT":
            object_register = flow["object_register"]
            class_register = row["base_register"]
            add(_reg(f"object-{object_register}", object_register, evidence))
            writer_rva = int(flow["nearest_target_register_writer"]["rva"])
            if probe_rva <= writer_rva:
                add(_scalar(f"class-{class_register}", f"object-{object_register}",
                            0, evidence))
            else:
                add(_reg(f"class-{class_register}", class_register, evidence))
            add(_scalar(f"class-name-pointer-{class_register}",
                        f"class-{class_register}", 0x50, evidence))
            add(_cstring(f"class-name-{class_register}",
                         f"class-name-pointer-{class_register}", evidence))
            add(_scalar(f"dispatch-target-{suffix}", f"class-{class_register}",
                        int(row["byte_offset"]), evidence))
        elif flow["status"] == "REGISTER_TARGET_LOADED_FROM_RECORD_FIELD":
            target_register = row["operands"].lower()
            record_register = flow["record_base_register"]
            writer_rva = int(flow["nearest_target_register_writer"]["rva"])
            if probe_rva > writer_rva:
                add(_reg(f"dispatch-target-{suffix}", target_register, evidence))
            # A load such as ``mov rax, [rax+0x100]`` destroys the record base.
            # At the later callsite only the exact target remains authoritative.
            if target_register != record_register or probe_rva <= writer_rva:
                record_base = _reg(f"record-base-{record_register}",
                                   record_register, evidence)
                if probe_rva <= writer_rva:
                    record_base["when"] = {"op": "neq", "value": 0}
                add(record_base)
                add(_scalar(f"record-target-{suffix}", f"record-base-{record_register}",
                            int(flow["record_field_offset"]), evidence))
        elif flow["status"] == "IL2CPP_DYNAMIC_VTABLE_SLOT_SHAPE":
            target_register = row["operands"].lower()
            class_register = flow["class_register"]
            slot_register = flow["slot_index_register"]
            add(_reg(f"dispatch-target-{suffix}", target_register, evidence))
            add(_reg(f"class-{class_register}", class_register, evidence))
            add(_scalar(f"class-name-pointer-{class_register}",
                        f"class-{class_register}", 0x50, evidence))
            add(_cstring(f"class-name-{class_register}",
                         f"class-name-pointer-{class_register}", evidence))
            add(_reg(f"vtable-slot-index-{slot_register}", slot_register, evidence))
        else:
            raise ValueError(f"unsupported dynamic dispatch form at {row['site_rva']:#x}")
    return reads


def build(indirect_path: Path, game_path: Path, class_layout_path: Path,
          closure_ledger_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    indirect = _load(indirect_path)
    if indirect.get("schema") != "uc.ability-executor-indirect-call-join.v1":
        raise ValueError("unsupported indirect call join")
    summary = indirect.get("summary", {})
    if (summary.get("indirect_callsites") != 353
            or summary.get("unique_runtime_slot_candidates_without_exact_identity") != 21):
        raise ValueError("indirect call accounting differs from the bounded v9 frontier")
    game_source = indirect["sources"]["game_module"]
    if (Path(game_source["path"]).resolve() != game_path.resolve()
            or file_hash(game_path) != game_source["sha256"]):
        raise ValueError("GameAssembly identity differs from indirect-call evidence")
    layout_text = class_layout_path.read_text(encoding="utf-8-sig")
    if "+0x50 | ptr | 类名（C 字符串）" not in layout_text or "+0xD0.. | ptr×N | 内联 vtable" not in layout_text:
        raise ValueError("audited Il2CppClass name/vtable layout changed")
    ledger = _load(closure_ledger_path)
    if ledger.get("schema") != "uc.controller-closure-state.v1" or ledger.get("runtime_required_now"):
        raise ValueError("controller closure ledger is not at the expected offline frontier")

    unresolved = [row for row in indirect["callsites"]
                  if row.get("resolution_status") == "STATIC_TARGET_UNRESOLVED"]
    slots = {int(row["slot_rva"])
             for row in indirect["callsites"]
             if row["dispatch_form"] == "RIP_GLOBAL_SLOT"
             and row.get("resolution_status") == "UNRESOLVED_RIP_SLOT_IDENTITY"}
    slots.update(int(row["local_dataflow"]["slot_rva"])
                 for row in unresolved
                 if row["dispatch_form"] == "REGISTER_TARGET"
                 and row["local_dataflow"]["status"] ==
                 "REGISTER_TARGET_LOADED_FROM_RIP_SLOT")
    slots = sorted(slots)
    if len(slots) != 21:
        raise ValueError(f"expected 21 unresolved initialized slots, got {len(slots)}")
    dynamic = [row for row in unresolved if row["dispatch_form"] == "OBJECT_OR_VTABLE_SLOT"
               or (row["dispatch_form"] == "REGISTER_TARGET"
                   and row["local_dataflow"]["status"] !=
                   "REGISTER_TARGET_LOADED_FROM_RIP_SLOT")]
    if len(dynamic) != 36:
        raise ValueError(f"expected 36 dynamic callsites after slot separation, got {len(dynamic)}")

    by_rva = {int(row["site_rva"]): row for row in dynamic}
    coalesced_secondary = 0x12D6489B
    coalesced_primary = 0x12D6488D
    if coalesced_primary not in by_rva or coalesced_secondary not in by_rva:
        raise ValueError("source-verified adjacent BulletMixin pair is absent")
    first, second = by_rva[coalesced_primary], by_rva[coalesced_secondary]
    if not (second["site_rva"] - first["site_rva"] == 14
            and first["caller_type"] == second["caller_type"] == "BulletMixin"
            and first["caller_method"] == second["caller_method"] == "CHKJBNIBGHF"
            and first["local_dataflow"]["object_register"] ==
                second["local_dataflow"]["object_register"] == "rdi"
            and first["base_register"] == second["base_register"] == "rax"
            and first["byte_offset"] == 0x100 and second["byte_offset"] == 0x110):
        raise ValueError("adjacent BulletMixin coalescing contract changed")

    # The SummonMixin ``call rax`` is followed immediately by a branch target,
    # so a 16-byte redirect at the call would overwrite an independently
    # reachable instruction.  Observe the exact argument-setup block 16 bytes
    # earlier; RAX already holds the mechanically tracked target and is not
    # modified by those three instructions.
    safe_probe_overrides = {
        # Gum 17.17 refuses an instruction listener whose first instruction is
        # these 2/3-byte register-indirect calls.  Observe the source-decoded
        # null-check block instead: the record pointer is already live and a
        # read predicate admits only the exact path that loads and calls it.
        0x0D847CFB: 0x0D847CE6,
        0x0D847E41: 0x0D847E2C,
        0x0D8489EB: 0x0D8489DB,
        # The call's following NOP is a direct branch target.  Probe after the
        # exact ``mov rax,[rsi]`` class load; the relocation window then ends
        # exactly at that target instead of overwriting it.
        0x0FEFA296: 0x0FEFA28B,
        0x124558B6: 0x124558B0,
        0x12CF2355: 0x12CF2338,
        0x12CF25F3: 0x12CF25E0,
        0x12CF2657: 0x12CF2644,
        0x12CF26BB: 0x12CF26A8,
        0x12CF3FE9: 0x12CF3FD1,
        0x12D643B5: 0x12D643AC,
        0x12D687D4: 0x12D687BD,
        0x144F9518: 0x144F9504,
        # The native interface lookup has two paths.  Both converge with R8
        # as the exact target and stack result slots at +0x50/+0x58.  RAX is
        # path-dependent here and is deliberately not labeled as a class.
        0x147FA574: 0x147FA56F,
        0x148E2ED7: 0x148E2EC6,
        0x148E31E2: 0x148E31DC,
        0x16EDD85A: 0x16EDD845,
        0x17893583: 0x1789356D,
        0x1789431F: 0x17894309,
    }
    record_null_check_probes = {
        0x0D847CE6, 0x0D847E2C, 0x12CF25E0, 0x12CF2644,
        0x12CF26A8, 0x12CF3FD1, 0x16EDD845,
    }
    summon_row = by_rva[0x0D8489EB]
    summon_flow = summon_row["local_dataflow"]
    if (summon_row["operands"].lower() != "rax"
            or summon_flow["nearest_target_register_writer"].get("rva") != 0x0D848940
            or summon_flow["nearest_target_register_writer"].get("bytes") !=
            "488b8000010000"):
        raise ValueError("SummonMixin safe pre-call target-register contract changed")
    record_probe_contracts = {
        0x0D847CFB: (0x0D847CEF, "4d8b7908", "r9", "r15"),
        0x0D847E41: (0x0D847E35, "4d8b7908", "r9", "r15"),
        0x12CF25F3: (0x12CF25E9, "4d8b7008", "r8", "r14"),
        0x12CF2657: (0x12CF264D, "4d8b7008", "r8", "r14"),
        0x12CF26BB: (0x12CF26B1, "4d8b7008", "r8", "r14"),
        0x12CF3FE9: (0x12CF3FDA, "498b7908", "r9", "rdi"),
        0x16EDD85A: (0x16EDD84E, "4d8b7908", "r9", "r15"),
    }
    for callsite, (writer_rva, writer_bytes, record_register,
                   target_register) in record_probe_contracts.items():
        row = by_rva[callsite]
        flow = row["local_dataflow"]
        writer = flow["nearest_target_register_writer"]
        if (flow.get("status") != "REGISTER_TARGET_LOADED_FROM_RECORD_FIELD"
                or flow.get("record_base_register") != record_register
                or row["operands"].lower() != target_register
                or writer.get("rva") != writer_rva
                or writer.get("bytes") != writer_bytes
                or int(flow.get("record_field_offset", -1)) != 8):
            raise ValueError(f"{callsite:#x}: register-record pre-call contract changed")
    dynamic_slot_row = by_rva[0x147FA574]
    dynamic_slot_writer = dynamic_slot_row[
        "local_dataflow"]["nearest_target_register_writer"]
    if (dynamic_slot_row["local_dataflow"].get("status") !=
            "IL2CPP_DYNAMIC_VTABLE_SLOT_SHAPE"
            or dynamic_slot_row["operands"].lower() != "r8"
            or dynamic_slot_writer.get("rva") != 0x147FA54B
            or dynamic_slot_writer.get("bytes") != "4c8b84c8d0000000"):
        raise ValueError("ModifyAttackDataAction converged target contract changed")
    emitter_row = by_rva[0x0FEFA296]
    emitter_writer = emitter_row["local_dataflow"]["nearest_target_register_writer"]
    if (emitter_row["base_register"] != "rax"
            or emitter_row["local_dataflow"]["object_register"] != "rsi"
            or emitter_writer.get("rva") != 0x0FEFA288
            or emitter_writer.get("bytes") != "488b06"):
        raise ValueError("BulletEmitterMixin safe pre-call class-register contract changed")
    lock_row = by_rva[0x124558B6]
    lock_writer = lock_row["local_dataflow"]["nearest_target_register_writer"]
    if (lock_row["base_register"] != "rax"
            or lock_row["local_dataflow"]["object_register"] != "rcx"
            or lock_writer.get("rva") != 0x124558AD
            or lock_writer.get("bytes") != "488b01"):
        raise ValueError("LockLifePropertyMixin safe pre-call class-register contract changed")
    attach_row = by_rva[0x12CF2355]
    attach_writer = attach_row["local_dataflow"]["nearest_target_register_writer"]
    if (attach_row["operands"].lower() != "rbx"
            or attach_row["local_dataflow"]["record_base_register"] != "r9"
            or attach_writer.get("rva") != 0x12CF2349
            or attach_writer.get("bytes") != "498b5908"):
        raise ValueError("AttachZoneTagWithModifierMixin pre-load contract changed")
    bullet_row = by_rva[0x12D643B5]
    bullet_writer = bullet_row["local_dataflow"]["nearest_target_register_writer"]
    if (bullet_row["base_register"] != "rax"
            or bullet_row["local_dataflow"]["object_register"] != "rdi"
            or bullet_writer.get("rva") != 0x12D643A9
            or bullet_writer.get("bytes") != "488b07"):
        raise ValueError("BulletMixin safe pre-call class-register contract changed")
    bullet_njp = by_rva[0x12D687D4]
    bullet_njp_writer = bullet_njp["local_dataflow"]["nearest_target_register_writer"]
    if (bullet_njp["base_register"] != "rax"
            or bullet_njp["local_dataflow"]["object_register"] != "rbx"
            or bullet_njp_writer.get("rva") != 0x12D687BA
            or bullet_njp_writer.get("bytes") != "488b03"):
        raise ValueError("BulletMixin NJPFEGGJHHC pre-call class contract changed")
    smooth_row = by_rva[0x144F9518]
    smooth_writer = smooth_row["local_dataflow"]["nearest_target_register_writer"]
    if (smooth_row["base_register"] != "rax"
            or smooth_row["local_dataflow"]["object_register"] != "rcx"
            or smooth_writer.get("rva") != 0x144F9501
            or smooth_writer.get("bytes") != "488b01"):
        raise ValueError("SmoothBlendAbilitySpecialMixin class contract changed")
    rotation_row = by_rva[0x148E2ED7]
    rotation_writer = rotation_row["local_dataflow"]["nearest_target_register_writer"]
    if (rotation_row["base_register"] != "rax"
            or rotation_row["local_dataflow"]["object_register"] != "rdi"
            or rotation_writer.get("rva") != 0x148E2EC3
            or rotation_writer.get("bytes") != "488b07"):
        raise ValueError("ConfigRotationToTarget Process class contract changed")
    rotation_slot6 = by_rva[0x148E31E2]
    rotation_slot6_writer = rotation_slot6[
        "local_dataflow"]["nearest_target_register_writer"]
    if (rotation_slot6["base_register"] != "rax"
            or rotation_slot6["local_dataflow"]["object_register"] != "rcx"
            or rotation_slot6_writer.get("rva") != 0x148E31DC
            or rotation_slot6_writer.get("bytes") != "488b01"):
        raise ValueError("ConfigRotationToTarget slot-6 class contract changed")
    property_row = by_rva[0x17893583]
    property_writer = property_row["local_dataflow"]["nearest_target_register_writer"]
    if (property_row["base_register"] != "rax"
            or property_row["local_dataflow"]["object_register"] != "rcx"
            or property_writer.get("rva") != 0x1789356A
            or property_writer.get("bytes") != "488b01"):
        raise ValueError("ActionsOnPropertyChangeMixin PNLKOFLFGML class contract changed")
    property_jod = by_rva[0x1789431F]
    property_jod_writer = property_jod[
        "local_dataflow"]["nearest_target_register_writer"]
    if (property_jod["base_register"] != "rax"
            or property_jod["local_dataflow"]["object_register"] != "rcx"
            or property_jod_writer.get("rva") != 0x17894306
            or property_jod_writer.get("bytes") != "488b01"):
        raise ValueError("ActionsOnPropertyChangeMixin JODGAACJFFF class contract changed")
    represented: dict[int, list[dict[str, Any]]] = {}
    for row in dynamic:
        site = int(row["site_rva"])
        if site == coalesced_secondary:
            continue
        probe = safe_probe_overrides.get(site, site)
        if probe in represented:
            raise ValueError(f"unplanned physical-site sharing at {probe:#x}")
        represented[probe] = [row]
    represented[coalesced_primary].append(second)
    image = NativePE(game_path)
    refs = ["indirect-call-join", "game-module", "class-layout", "closure-ledger"]
    points = []
    qualification_rows = []
    contracts = []
    near_only_sites = 0
    interior_targets: set[int] = set()
    windows: dict[int, tuple[bytes, int, list[dict[str, Any]]]] = {}
    physical_rvas = [ANCHOR_RVA, *sorted(represented)]
    for rva in physical_rvas:
        prefix, span, instructions = _instruction_window(image, rva)
        windows[rva] = (prefix, span, instructions)
        interior_targets.update(range(rva + 1, rva + span))
    edges = image.direct_control_xrefs(interior_targets)
    edges_by_target: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        edges_by_target[int(edge["target_rva"])].append(edge)

    anchor_prefix, anchor_span, anchor_instructions = windows[ANCHOR_RVA]
    anchor_inside = [edge for target, rows in edges_by_target.items()
                     if ANCHOR_RVA < target < ANCHOR_RVA + anchor_span for edge in rows]
    if anchor_inside:
        raise ValueError("direct control edge enters anchor relocation interior")
    anchor_reads = [_scalar(f"initialized-slot-{slot:x}", "module:game", slot, refs)
                    for slot in slots]
    anchor_id = "AbilityDispatch.InitializedSlots@0x1e45eef0"
    points.append({"id": anchor_id, "backend": "gum_probe", "module": "game",
                   "rva": ANCHOR_RVA, "expected_prefix": anchor_prefix.hex(),
                   "reads": anchor_reads, "evidence": refs,
                   "capture_purpose": "one low-frequency snapshot of 21 initialized dispatch slots",
                   "interpretation": "raw module-relative slot values; no callee names assigned"})
    qualification_rows.append({
        "id": anchor_id + "/entry", "module": "game", "rva": ANCHOR_RVA,
        "verified_source_prefix": anchor_prefix.hex(), "semantic_safe_span": anchor_span,
        "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True,
        "static_evidence": {"instruction_boundary_span": anchor_span,
                            "instructions": anchor_instructions,
                            "direct_edge_scan_scope": "all-file-backed-executable-sections",
                            "direct_interior_edges": []},
    })

    for rva in sorted(represented):
        rows = represented[rva]
        prefix, span, instructions = windows[rva]
        inside = [edge for target, edge_rows in edges_by_target.items()
                  if rva < target < rva + span for edge in edge_rows]
        safe_spans = [5, 16]
        qualified_span = span
        if inside:
            first_instruction = instructions[0]
            callsite_rvas = {int(row["site_rva"]) for row in rows}
            if rva in record_null_check_probes:
                if ([row["mnemonic"] for row in instructions[:3]] !=
                        ["test", "je", "mov"]
                        or sum(row["size"] for row in instructions[:3]) != 13
                        or any(edge["target_rva"] != rva + 13 for edge in inside)):
                    raise ValueError(f"{rva:#x}: null-check branch boundary changed")
                # The later argument-setup instruction is an independent loop
                # target.  A near redirect needs only the preceding whole
                # test/branch/load block; a far redirect is not authorized.
                qualified_span = 13
            else:
                if (callsite_rvas != {rva} or first_instruction["rva"] != rva
                        or first_instruction["mnemonic"] != "call"
                        or first_instruction["size"] < 5):
                    raise ValueError(f"{rva:#x}: direct control edge enters relocation interior")
                qualified_span = int(first_instruction["size"])
                if any(rva < edge["target_rva"] < rva + qualified_span
                       for edge in inside):
                    raise ValueError(f"{rva:#x}: direct edge enters the near relocation instruction")
            safe_spans = [5]
            near_only_sites += 1
        point_id = f"AbilityDispatch.Dynamic@0x{rva:x}"
        points.append({"id": point_id, "backend": "gum_probe", "module": "game",
                       "rva": rva, "expected_prefix": prefix.hex(),
                       "reads": _dynamic_reads(rows, refs, rva), "evidence": refs,
                       "capture_purpose": "dynamic dispatch target and receiver/class evidence",
                       "interpretation": "raw pre-call instruction state; no semantic callee identity inferred"})
        qualification_rows.append({
            "id": point_id + "/entry", "module": "game", "rva": rva,
            "verified_source_prefix": prefix.hex(), "semantic_safe_span": qualified_span,
            "safe_redirect_spans": safe_spans, "direct_interior_edge_free": True,
            "static_evidence": {"instruction_boundary_span": qualified_span,
                                "instructions": [row for row in instructions
                                                 if row["rva"] < rva + qualified_span],
                                "direct_edge_scan_scope": "all-file-backed-executable-sections",
                                "direct_interior_edges": []},
        })
        contracts.append({
            "physical_probe_rva": rva,
            "represented_callsites": [{
                "site_rva": int(row["site_rva"]), "caller_type": row["caller_type"],
                "caller_method": row["caller_method"], "dispatch_form": row["dispatch_form"],
                "operands": row["operands"], "local_dataflow": row["local_dataflow"],
            } for row in rows],
            "probe_rva_differs_from_callsite": any(
                int(row["site_rva"]) != rva for row in rows),
            "coalesced_adjacent_fallthrough": len(rows) > 1,
            "semantic_safe_span": qualified_span,
            "safe_redirect_spans": safe_spans,
        })

    sources = {
        "indirect-call-join": _source(indirect_path), "game-module": _source(game_path),
        "class-layout": _source(class_layout_path), "closure-ledger": _source(closure_ledger_path),
        "plan-generator": _source(Path(__file__)),
    }
    plan = {
        "schema": "uc.capture-plan.v1", "plan_id": "ability-dynamic-dispatch-v1",
        "plan_revision": 1,
        "modules": {"game": {"image": game_path.name, "sha256": file_hash(game_path)}},
        "sources": sources,
        # Pools are per observation and continuously recycled by the worker;
        # 1024 slots provide burst headroom without exceeding the observer's
        # fixed 256 MiB combined preallocation ceiling across 36 points.
        "resources": {"slots_per_point": 1024, "max_record_bytes": 2048,
                      "capture_xmm": False},
        "points": points,
        "scope": {"purpose": "resolve raw initialized-slot and dynamic dispatch identities",
                  "automatic_stop": False, "fixed_duration": False,
                  "snapshot_limit": False, "semantic_callee_names_assigned": False,
                  "physical_dynamic_sites": len(represented),
                  "represented_dynamic_callsites": len(dynamic)},
    }
    validate(plan, verify_sources=True)
    qualification = {
        "schema": "uc.probe-site-qualification.v1",
        "qualification_id": "ability-dispatch-" + hashlib.sha256(
            canonical({"plan": plan["plan_id"], "revision": plan["plan_revision"],
                       "sites": qualification_rows})).hexdigest()[:16],
        "modules": plan["modules"], "sites": qualification_rows,
    }
    validate_site_qualification(qualification)
    contract = {
        "schema": "uc.ability-dynamic-dispatch-static-contract.v1",
        "sources": sources,
        "summary": {"unresolved_initialized_slots": len(slots),
                    "dynamic_callsites": len(dynamic),
                    "physical_dynamic_probe_sites": len(represented),
                    "coalesced_adjacent_callsites": len(dynamic) - len(represented),
                    "qualification_sites": len(qualification_rows),
                    "near_only_qualification_sites": near_only_sites,
                    "direct_relocation_interior_edges": 0},
        "initialized_slot_rvas": slots,
        "dynamic_dispatch_contracts": contracts,
        "bounded_conclusions": [
            "slot values and dispatch targets are raw runtime addresses and are not semantic method names",
            "object class names come from the audited Il2CppClass +0x50 C-string pointer",
            "the adjacent BulletMixin calls are coalesced only because exact fallthrough reloads the same object class before the second slot call",
            "absence of a dynamic-site record is not non-execution unless the activated point has complete loss accounting for the declared window",
        ],
    }
    out.mkdir(parents=True)
    plan_path = out / "capture-plan.ability-dynamic-dispatch.json"
    qualification_path = out / "qualification.json"
    contract_path = out / "ability-dynamic-dispatch-static-contract.json"
    plan_path.write_bytes(canonical(plan))
    qualification_path.write_bytes(canonical(qualification))
    contract_path.write_bytes(canonical(contract))
    report = {
        "schema": "uc.ability-dynamic-dispatch-plan-report.v1",
        "plan": _source(plan_path), "qualification": _source(qualification_path),
        "static_contract": _source(contract_path), **contract["summary"],
        "activation_ready": False, "runtime_required_now": True,
        "next_step": "qualify all 36 physical sites in one target process before activation",
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indirect", type=Path, default=DEFAULT_INDIRECT)
    parser.add_argument("--game", type=Path, default=DEFAULT_GAME)
    parser.add_argument("--class-layout", type=Path, default=DEFAULT_LAYOUT)
    parser.add_argument("--closure-ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.indirect.resolve(), args.game.resolve(),
                     args.class_layout.resolve(), args.closure_ledger.resolve(),
                     args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_dynamic_dispatch_plan", error, {
            "indirect": str(args.indirect), "game": str(args.game),
            "class_layout": str(args.class_layout),
            "closure_ledger": str(args.closure_ledger),
        })
        raise


if __name__ == "__main__":
    run_main(main)
