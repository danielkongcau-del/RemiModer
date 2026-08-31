"""Scan exact GameAssembly PDATA bodies for RIP-relative initialized-slot xrefs."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from capstone import CS_AC_READ, CS_AC_WRITE
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _access_kind(access: int) -> str:
    read = bool(access & CS_AC_READ)
    write = bool(access & CS_AC_WRITE)
    if read and write:
        return "READ_WRITE"
    if write:
        return "WRITE"
    if read:
        return "READ"
    return "ACCESS_UNSPECIFIED_BY_DECODER"


def build(consumer_join_path: Path, game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    consumer_join = _load(consumer_join_path)
    if consumer_join.get("schema") != "uc.ability-initialized-slot-consumer-join.v1":
        raise ValueError("unsupported initialized-slot consumer join")
    slot_rvas = {int(row["slot_rva"]) for row in consumer_join["initialized_slots"]
                 if row["slot_identity"] != "PE_IMPORT_ADDRESS_TABLE"}
    if len(slot_rvas) != 18:
        raise ValueError("expected 18 non-import slots")
    image = NativePE(game_path)
    refs: dict[tuple[int, int, int, str], dict[str, Any]] = {}
    decoded_complete = 0
    decoded_incomplete = 0
    for function in image.runtime_functions:
        raw = image.bytes_at(function.begin, function.end - function.begin)
        cursor = function.begin
        function_complete = True
        for ins in image.cs.disasm(raw, image.image_base + function.begin):
            rva = int(ins.address - image.image_base)
            if rva != cursor:
                function_complete = False
                break
            for operand_index, operand in enumerate(ins.operands):
                if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
                    continue
                referenced_rva = rva + ins.size + int(operand.mem.disp)
                if referenced_rva not in slot_rvas:
                    continue
                kind = _access_kind(int(operand.access))
                key = (rva, referenced_rva, operand_index, kind)
                refs[key] = {
                    "site_rva": rva, "bytes": ins.bytes.hex(),
                    "mnemonic": ins.mnemonic, "operands": ins.op_str,
                    "operand_index": operand_index, "access": kind,
                    "slot_rva": referenced_rva,
                    "pdata_begin_rva": function.begin, "pdata_end_rva": function.end,
                }
            cursor += ins.size
        if cursor != function.end:
            function_complete = False
        if function_complete:
            decoded_complete += 1
        else:
            decoded_incomplete += 1
    rows = sorted(refs.values(), key=lambda row: (row["slot_rva"], row["site_rva"]))
    access_counts = Counter(row["access"] for row in rows)
    write_slots = {row["slot_rva"] for row in rows
                   if row["access"] in ("WRITE", "READ_WRITE")}
    referenced_slots = {row["slot_rva"] for row in rows}
    summary = {
        "non_import_slots": len(slot_rvas),
        "pdata_records": len(image.runtime_functions),
        "fully_linearly_decoded_pdata_records": decoded_complete,
        "incompletely_linearly_decoded_pdata_records": decoded_incomplete,
        "exact_rip_relative_references": len(rows),
        "referenced_slots": len(referenced_slots),
        "slots_with_pdata_write_reference": len(write_slots),
        "slots_without_pdata_write_reference": len(slot_rvas - write_slots),
        "access_counts": dict(sorted(access_counts.items())),
    }
    artifact = {
        "schema": "uc.ability-initialized-slot-pdata-xrefs.v1",
        "sources": {"consumer_join": _source(consumer_join_path),
                    "game_module": _source(game_path)},
        "summary": summary,
        "bounded_conclusions": [
            "each row is an exact Capstone-decoded RIP-relative memory operand inside a declared GameAssembly PDATA range",
            "decoder access flags are preserved; unspecified access is not promoted to read or write",
            "absence of a write reference covers only decoded PDATA bodies and does not exclude loader, relocation, pdata-less, or external initialization",
            "the scan is static and did not start or attach to the game",
        ],
        "runtime_needed_now": False,
        "slots_without_pdata_write_reference": sorted(slot_rvas - write_slots),
        "references": rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-initialized-slot-pdata-xrefs.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-initialized-slot-pdata-xrefs-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-join", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.consumer_join.resolve(), args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_initialized_slot_pdata_xrefs", error,
                      {"consumer_join": str(args.consumer_join), "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
