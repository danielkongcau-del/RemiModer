"""Join captured initialized slots to exact static Ability callsite consumers."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _callsite_slot(row: dict[str, Any]) -> int | None:
    if row.get("slot_rva") is not None:
        return int(row["slot_rva"])
    local = row.get("local_dataflow", {})
    if local.get("slot_rva") is not None:
        return int(local["slot_rva"])
    return None


def join(slot_import: dict[str, Any], indirect: dict[str, Any]) -> dict[str, Any]:
    if slot_import.get("schema") != "uc.ability-initialized-slot-import-join.v1":
        raise ValueError("unsupported initialized-slot import join")
    if indirect.get("schema") != "uc.ability-executor-indirect-call-join.v1":
        raise ValueError("unsupported Ability indirect-call join")
    consumers: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in indirect["callsites"]:
        slot_rva = _callsite_slot(row)
        if slot_rva is None:
            continue
        consumer = {
            "site_rva": int(row["site_rva"]),
            "caller_type": row.get("caller_type"),
            "caller_method": row.get("caller_method"),
            "caller_role": row.get("caller_role"),
            "dispatch_form": row.get("dispatch_form"),
            "resolution_status": row.get("resolution_status"),
            "access_form": ("DIRECT_RIP_CALL_SLOT" if row.get("slot_rva") is not None
                            else "RIP_SLOT_LOADED_TO_REGISTER"),
        }
        if consumer not in consumers[slot_rva]:
            consumers[slot_rva].append(consumer)
    rows = []
    for slot in slot_import["initialized_slots"]:
        rva = int(slot["slot_rva"])
        matches = sorted(consumers.get(rva, []), key=lambda row: row["site_rva"])
        rows.append({
            **slot,
            "static_consumers": matches,
            "consumer_status": ("EXACT_STATIC_CONSUMERS" if matches
                                else "NO_SELECTED_ABILITY_CONSUMER"),
            "initialization_owner_status": (
                "PE_IMPORT_DESCRIPTOR" if slot.get("import")
                else "UNRESOLVED_NON_IMPORT_INITIALIZER"),
        })
    non_import = [row for row in rows if row.get("import") is None]
    return {
        "initialized_slots": rows,
        "summary": {
            "initialized_slots": len(rows),
            "slots_with_static_consumers": sum(bool(row["static_consumers"])
                                                for row in rows),
            "static_consumer_callsites": sum(len(row["static_consumers"])
                                               for row in rows),
            "pe_import_slots": sum(row.get("import") is not None for row in rows),
            "non_import_slots": len(non_import),
            "non_import_slots_with_static_consumers": sum(
                bool(row["static_consumers"]) for row in non_import),
            "non_import_slots_with_unresolved_initializer": sum(
                row["initialization_owner_status"] == "UNRESOLVED_NON_IMPORT_INITIALIZER"
                for row in non_import),
        },
    }


def analyze(slot_import_path: Path, indirect_path: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    result = {
        "schema": "uc.ability-initialized-slot-consumer-join.v1",
        "sources": {
            "initialized_slot_import_join": _source(slot_import_path),
            "ability_indirect_call_join": _source(indirect_path),
        },
        "bounded_conclusions": [
            "consumer ownership is an exact slot-RVA to decoded-callsite join",
            "a consumer does not identify the process module or routine stored in a non-import slot",
            "non-import initializer identity remains unresolved until a writer or registration record is found",
        ],
        **join(_load(slot_import_path), _load(indirect_path)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(result))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("initialized_slot_import_join", type=Path)
    parser.add_argument("ability_indirect_call_join", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.initialized_slot_import_join,
                         args.ability_indirect_call_join, args.output)
    except Exception as error:
        write_failure(args.output, "ability_initialized_slot_consumer_join", error, {
            "initialized_slot_import_join": str(args.initialized_slot_import_join),
            "ability_indirect_call_join": str(args.ability_indirect_call_join),
        })
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
