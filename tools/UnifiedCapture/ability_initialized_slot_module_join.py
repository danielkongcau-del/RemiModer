"""Resolve external initialized-slot targets by ASLR-translated PDATA set matching."""
from __future__ import annotations

import argparse
import hashlib
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


def _candidate_bases(targets: set[int], starts: set[int], image_size: int,
                     containing: Any | None = None) -> list[dict[str, int]]:
    minimum = min(targets)
    lo = ((minimum - image_size) // 0x10000) * 0x10000
    hi = (minimum // 0x10000) * 0x10000
    rows = []
    for base in range(lo, hi + 1, 0x10000):
        exact = sum((target - base) in starts for target in targets)
        interior = (sum(containing(target - base) is not None for target in targets)
                    if containing is not None else exact)
        if exact or interior:
            rows.append({"runtime_base": base, "exact_pdata_starts": exact,
                         "inside_pdata_ranges": interior})
    return sorted(rows, key=lambda row: (-row["exact_pdata_starts"],
                                         -row["inside_pdata_ranges"],
                                         row["runtime_base"]))


def build(consumer_join_path: Path, module_dir: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    consumer_join = _load(consumer_join_path)
    if consumer_join.get("schema") != "uc.ability-initialized-slot-consumer-join.v1":
        raise ValueError("unsupported initialized-slot consumer join")
    slots = [row for row in consumer_join["initialized_slots"]
             if row["slot_identity"] != "PE_IMPORT_ADDRESS_TABLE"]
    if len(slots) != 18:
        raise ValueError("expected 18 non-import initialized slots")
    targets = {int(row["values"][0]["address"]) for row in slots}
    if any(len(row["values"]) != 1 or not row["stable"] for row in slots):
        raise ValueError("non-import slot targets are not single-valued and stable")

    module_rows = []
    for path in sorted(module_dir.glob("*.dll")):
        try:
            image = NativePE(path)
        except ValueError:
            continue
        candidates = _candidate_bases(
            targets, set(image.by_start), image.size_of_image, image.containing)
        best = candidates[0] if candidates else {
            "runtime_base": None, "exact_pdata_starts": 0, "inside_pdata_ranges": 0}
        module_rows.append({"path": str(path.resolve()), "file_size": path.stat().st_size,
                            "image_size": image.size_of_image,
                            "pdata_entries": len(image.runtime_functions),
                            "best_candidate": best,
                            "full_exact_candidate_bases": [row["runtime_base"] for row in candidates
                                                           if row["exact_pdata_starts"] == len(targets)]})
    full = [(row, base) for row in module_rows for base in row["full_exact_candidate_bases"]]
    if len(full) != 1:
        raise ValueError(f"expected one full exact module/base match, got {len(full)}")
    selected_row, runtime_base = full[0]
    selected_path = Path(selected_row["path"])
    selected = NativePE(selected_path)
    resolved_slots = []
    for slot in slots:
        address = int(slot["values"][0]["address"])
        rva = address - runtime_base
        function = selected.by_start.get(rva)
        if function is None:
            raise ValueError(f"selected module lacks exact target PDATA entry: {address:#x}")
        raw = selected.bytes_at(function.begin, function.end - function.begin)
        resolved_slots.append({
            "slot_rva": int(slot["slot_rva"]), "runtime_target_address": address,
            "module": selected_path.name, "module_runtime_base": runtime_base,
            "target_rva": rva, "pdata_begin_rva": function.begin,
            "pdata_end_rva": function.end, "body_sha256": hashlib.sha256(raw).hexdigest(),
            "body_prefix": raw[:32].hex(),
            "static_consumer_callsites": len(slot["static_consumers"]),
            "static_consumers": slot["static_consumers"],
            "initializer_owner_status": "TARGET_MODULE_RESOLVED_INITIALIZER_WRITE_SITE_UNRESOLVED",
        })
    leaderboard = sorted(module_rows, key=lambda row: (
        -row["best_candidate"]["exact_pdata_starts"],
        -row["best_candidate"]["inside_pdata_ranges"], row["path"]))
    summary = {
        "non_import_slots": len(slots), "unique_runtime_targets": len(targets),
        "candidate_modules_scanned": len(module_rows),
        "unique_full_exact_module_base_matches": len(full),
        "slots_with_exact_module_pdata_target": len(resolved_slots),
        "unique_exact_module_pdata_targets": len({row["target_rva"] for row in resolved_slots}),
        "initializer_write_sites_resolved": 0,
        "selected_module": selected_path.name,
        "selected_runtime_base": runtime_base,
    }
    artifact = {
        "schema": "uc.ability-initialized-slot-module-join.v1",
        "sources": {"consumer_join": _source(consumer_join_path),
                    "selected_module": _source(selected_path)},
        "summary": summary,
        "module_candidate_leaderboard": leaderboard,
        "bounded_conclusions": [
            "the selected module/base is the unique 64-KiB-aligned translation mapping every distinct runtime target to an exact PDATA entry among scanned local game-root DLLs",
            "module and RVA identity do not by themselves identify exported or internal function semantics",
            "target-module recovery does not identify the code that initialized each GameAssembly slot",
            "all module candidates and target files are local; no game process was started or attached",
        ],
        "runtime_needed_now": False,
        "slots": sorted(resolved_slots, key=lambda row: row["slot_rva"]),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-initialized-slot-module-join.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-initialized-slot-module-join-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-join", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.consumer_join.resolve(), args.module_dir.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_initialized_slot_module_join", error,
                      {"consumer_join": str(args.consumer_join),
                       "module_dir": str(args.module_dir)})
        raise


if __name__ == "__main__":
    run_main(main)
