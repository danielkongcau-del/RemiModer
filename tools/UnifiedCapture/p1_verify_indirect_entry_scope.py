"""Narrow unknown incoming edges for one exit window without claiming closure."""
from __future__ import annotations

import argparse
import copy
import json
import struct
from pathlib import Path

import numpy as np
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest


def run(manifest_path: Path, function_id: str, minimum_span: int, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    value = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(value)
    function = next(row for row in value["functions"] if row["function_id"] == function_id)
    candidates = [(site, candidate) for site in function["normal_exits"]
                  for candidate in site["probe_candidates"]
                  if candidate["candidate_for_minimum_span"] == minimum_span]
    if len(candidates) != 1:
        raise ValueError("candidate span class is not unique")
    exit_site, candidate = candidates[0]
    sources = {row["alias"]: row for row in value["sources"] if row.get("kind") == "module"}
    source = sources[function["module"]]
    image = NativePE(Path(source["path"]))
    if file_hash(image.path) != function["module_sha256"]:
        raise ValueError("module identity changed")
    start = candidate["probe_rva"]
    interior = set(range(start + 1, start + candidate["available_span_through_ret"]))
    direct = image.direct_control_xrefs(interior)
    if direct:
        raise ValueError("direct incoming edge exists")
    instruction_interiors = set(candidate["instruction_rvas"][1:])
    raw_hits = []
    for target in sorted(instruction_interiors):
        for width, encoded, kind in ((4, struct.pack("<I", target), "rva32"),
                                      (8, struct.pack("<Q", image.image_base + target), "va64")):
            cursor = 0
            while True:
                pos = image.data.find(encoded, cursor)
                if pos < 0:
                    break
                raw_hits.append({"target_rva": target, "file_offset": pos, "encoding": kind, "width": width})
                cursor = pos + 1
    materializations = []
    possible_rip_displacements = set()
    # A RIP-relative reference stores disp32.  For each possible displacement
    # byte position, the instruction may end 0..8 bytes after disp32 (an
    # immediate may follow it).  Vectorized raw arithmetic finds every such
    # encoding without decoding hundreds of MiB into Python instruction objects.
    for section in image.sections:
        if not section["flags"] & 0x20000000:
            continue
        raw = image.data[section["raw_pointer"]:section["raw_pointer"] + section["raw_size"]]
        view = np.ndarray(shape=(max(0, len(raw)-3),), dtype="<i4", buffer=raw, strides=(1,))
        for begin in range(0, len(view), 8 * 1024 * 1024):
            end = min(len(view), begin + 8 * 1024 * 1024)
            displacement = view[begin:end].astype(np.int64, copy=False)
            positions = np.arange(begin, end, dtype=np.int64)
            for tail in range(9):
                targets = section["rva"] + positions + 4 + tail + displacement
                mask = np.zeros(targets.shape, dtype=bool)
                for target in interior:
                    mask |= targets == target
                for relative in np.flatnonzero(mask):
                    dpos = begin + int(relative)
                    possible_rip_displacements.add((section["rva"] + dpos, tail, int(targets[relative])))
        for displacement_rva, tail, target in sorted(possible_rip_displacements):
            if not (section["rva"] <= displacement_rva < section["rva"] + len(raw)):
                continue
            dpos = displacement_rva - section["rva"]
            instruction_end = dpos + 4 + tail
            for start_offset in range(max(0, dpos-11), dpos+1):
                decoded = list(image.cs.disasm(raw[start_offset:instruction_end],
                    image.image_base + section["rva"] + start_offset, count=1))
                if len(decoded) != 1:
                    continue
                ins = decoded[0]
                if ins.size != instruction_end-start_offset or ins.disp_size != 4 or \
                        start_offset + ins.disp_offset != dpos:
                    continue
                if not any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and
                           ins.address + ins.size + op.mem.disp - image.image_base == target
                           for op in ins.operands):
                    continue
                site_rva = ins.address-image.image_base
                owner = image.containing(site_rva)
                boundary = bool(owner and any(row["rva"] == site_rva for row in image.decode(owner)["instructions"]))
                materializations.append({"site_rva": site_rva, "target_rva": target,
                    "kind": "rip-relative-address", "bytes": ins.bytes.hex(), "mnemonic": ins.mnemonic,
                    "operands": ins.op_str, "pdata_capstone_boundary_verified": boundary})
    candidate["incoming_edge_evidence"] = {
        "direct_control_edges": direct,
        "raw_exact_rva_or_va_encodings_at_interior_instruction_boundaries": raw_hits,
        "decoded_address_materializations_into_any_interior_byte": materializations,
        "raw_possible_rip_disp32_encodings": [
            {"displacement_rva": row[0], "bytes_after_disp32": row[1], "target_rva": row[2]}
            for row in sorted(possible_rip_displacements)],
        "global_indirect_control_transfer_instructions": None,
        "selected_function_resolved_indirect_branches": function["capstone_cfg"]["resolved_indirect_branches"],
        "selected_function_terminal_semantics_complete": function["completeness"]["normal_exit_set_complete"],
        "scope": "all file-backed executable sections plus whole-file exact RVA/VA encodings",
        "remaining_unknown": "runtime-computed cross-function indirect target cannot be excluded statically"}
    candidate["incoming_edges_complete"] = False
    value["summary"]["selected_candidates_with_no_static_interior_reference"] = int(
        not direct and not raw_hits and not materializations)
    output.mkdir(parents=True)
    destination = output / "native-exit-manifest.indirect-scope-narrowed.json"
    destination.write_bytes(canonical(value))
    report = {"schema": "uc.indirect-entry-scope-verification.v1", "function_id": function_id,
              "exit_site_id": exit_site["exit_site_id"], "probe_rva": start,
              "static_direct_edges": len(direct), "raw_pointer_encodings": len(raw_hits),
              "decoded_address_materializations": len(materializations),
              "raw_possible_rip_disp32_encodings": len(possible_rip_displacements),
              "global_indirect_control_transfers": None,
              "incoming_edges_complete": False,
              "remaining_unknown": "runtime-computed cross-function indirect target",
              "activation_ready": False, "manifest": {"path": str(destination),
                                                        "sha256": file_hash(destination)}}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "manifest": str(destination),
                      "static_interior_references": len(direct)+len(raw_hits)+len(materializations),
                      "raw_possible_rip_disp32_encodings": len(possible_rip_displacements),
                      "incoming_edges_complete": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--function-id", required=True)
    parser.add_argument("--minimum-span", type=int, default=16)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.function_id, args.minimum_span, args.out.resolve())
