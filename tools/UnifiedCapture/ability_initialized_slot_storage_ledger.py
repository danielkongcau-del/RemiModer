"""Classify initialized-slot PE storage and bound the remaining initializer provenance gap."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _classify_rva(image: NativePE, rva: int) -> dict[str, Any]:
    matches = [section for section in image.sections
               if section["rva"] <= rva < section["rva"] + section["virtual_size"]]
    if len(matches) != 1:
        raise ValueError(f"RVA has {len(matches)} virtual-section matches: {rva:#x}")
    section = matches[0]
    relative = rva - section["rva"]
    file_backed = relative < section["raw_size"]
    return {
        "section": section["name"],
        "section_rva": section["rva"],
        "section_virtual_size": section["virtual_size"],
        "section_raw_size": section["raw_size"],
        "section_raw_pointer": section["raw_pointer"],
        "section_relative_offset": relative,
        "file_backed": file_backed,
        "storage_class": "FILE_BACKED" if file_backed else "VIRTUAL_ZERO_FILL_TAIL",
        "file_offset": section["raw_pointer"] + relative if file_backed else None,
    }


def build(module_join_path: Path, pdata_xrefs_path: Path,
          game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    module_join = _load(module_join_path)
    pdata_xrefs = _load(pdata_xrefs_path)
    if module_join.get("schema") != "uc.ability-initialized-slot-module-join.v1":
        raise ValueError("unsupported initialized-slot module join")
    if pdata_xrefs.get("schema") != "uc.ability-initialized-slot-pdata-xrefs.v1":
        raise ValueError("unsupported initialized-slot PDATA xrefs")
    if module_join["summary"]["non_import_slots"] != 18:
        raise ValueError("expected 18 non-import slots in module join")
    if pdata_xrefs["summary"]["non_import_slots"] != 18:
        raise ValueError("expected 18 non-import slots in PDATA xrefs")

    image = NativePE(game_path)
    no_write = set(map(int, pdata_xrefs["slots_without_pdata_write_reference"]))
    slots = []
    for source in module_join["slots"]:
        slot_rva = int(source["slot_rva"])
        storage = _classify_rva(image, slot_rva)
        slots.append({
            "slot_rva": slot_rva,
            **storage,
            "runtime_target_module": source["module"],
            "runtime_target_rva": int(source["target_rva"]),
            "runtime_target_address": int(source["runtime_target_address"]),
            "no_write_reference_in_decoded_gameassembly_pdata": slot_rva in no_write,
            "initializer_provenance_status": (
                "ZERO_FILL_STORAGE_RUNTIME_VALUE_OBSERVED_"
                "NO_WRITE_IN_DECODED_GAMEASSEMBLY_PDATA_INITIALIZER_UNRESOLVED"),
        })
    if len(slots) != 18 or len({row["slot_rva"] for row in slots}) != 18:
        raise ValueError("slot ledger is not an exact 18-slot set")

    storage_counts: dict[str, int] = {}
    for row in slots:
        storage_counts[row["storage_class"]] = storage_counts.get(row["storage_class"], 0) + 1
    summary = {
        "slots": len(slots),
        "storage_counts": dict(sorted(storage_counts.items())),
        "slots_in_data_section": sum(row["section"] == ".data" for row in slots),
        "slots_without_file_backed_initial_value": sum(not row["file_backed"] for row in slots),
        "slots_without_decoded_gameassembly_pdata_write_reference": sum(
            row["no_write_reference_in_decoded_gameassembly_pdata"] for row in slots),
        "slots_with_exact_runtime_target_module_rva": sum(
            row["runtime_target_module"] and row["runtime_target_rva"] >= 0 for row in slots),
        "initializer_write_sites_resolved": 0,
    }
    artifact = {
        "schema": "uc.ability-initialized-slot-storage-ledger.v1",
        "sources": {
            "module_join": _source(module_join_path),
            "pdata_xrefs": _source(pdata_xrefs_path),
            "game_module": _source(game_path),
        },
        "summary": summary,
        "bounded_conclusions": [
            "every listed slot RVA is classified against the exact PE section table of the supplied GameAssembly file",
            "VIRTUAL_ZERO_FILL_TAIL means the RVA is inside section virtual size but beyond that section's file-backed raw size",
            "a zero-fill storage location has no pointer initial value encoded at that RVA in the supplied GameAssembly file",
            "the PDATA-xref absence covers decoded GameAssembly PDATA bodies only and does not exclude loader, relocation, pdata-less, or external initialization",
            "the observed runtime target module and RVA are preserved without assigning function semantics or initializer ownership",
        ],
        "runtime_needed_now": False,
        "slots": sorted(slots, key=lambda row: row["slot_rva"]),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-initialized-slot-storage-ledger.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-initialized-slot-storage-ledger-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-join", type=Path, required=True)
    parser.add_argument("--pdata-xrefs", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.module_join.resolve(), args.pdata_xrefs.resolve(),
                     args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_initialized_slot_storage_ledger", error,
                      {"module_join": str(args.module_join),
                       "pdata_xrefs": str(args.pdata_xrefs), "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
