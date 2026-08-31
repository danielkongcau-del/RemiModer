"""Analyze one sealed Ability dynamic-dispatch capture without naming callees.

The report preserves the distinction between raw addresses, GameAssembly
relative addresses, observed class-name bytes, and semantic identity.  A
complete zero-loss window proves only that an installed point was not observed
in that window; it does not prove that the represented gameplay behavior did
not execute by some other path.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.probe_pair import compile_probe_pair
from uc.store import (decode_chunk_file, event_dictionary_context,
                      inspect_session, read_manifest)


ANCHOR_PREFIX = "AbilityDispatch.InitializedSlots@"
DYNAMIC_PREFIX = "AbilityDispatch.Dynamic@"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _address(value: int, module_base: int, module_size: int) -> dict[str, Any]:
    result: dict[str, Any] = {"address": int(value)}
    if not value:
        result["classification"] = "NULL"
    elif module_base <= value < module_base + module_size:
        result.update(classification="GAME_MODULE_RVA", rva=value - module_base)
    else:
        result["classification"] = "EXTERNAL_ABSOLUTE_ADDRESS"
    return result


def _read_blob(read: dict[str, Any], blob: bytes) -> bytes:
    begin, length = int(read["offset"]), int(read["length"])
    if begin < 0 or length < 0 or begin + length > len(blob):
        raise ValueError(f"read payload range is outside record blob: {read['id']}")
    return blob[begin:begin + length]


def _class_name(read: dict[str, Any], blob: bytes) -> str:
    raw = _read_blob(read, blob).split(b"\0", 1)[0]
    return raw.decode("utf-8", errors="backslashreplace")


def _checkpoint_windows(checkpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checkpoints = sorted(checkpoints, key=lambda row: int(row["checkpoint_id"]))
    windows = []
    for left, right in zip(checkpoints, checkpoints[1:]):
        begin = int(left["snapshot_end_qpc"])
        end = int(right["snapshot_begin_qpc"])
        if end < begin:
            raise ValueError("checkpoint interior QPC order is inverted")
        windows.append({
            "id": f"{left['label']}->{right['label']}",
            "from_checkpoint_id": int(left["checkpoint_id"]),
            "to_checkpoint_id": int(right["checkpoint_id"]),
            "begin_qpc_exclusive": begin,
            "end_qpc_exclusive": end,
            "boundary_semantics": "conservative_interior_between_non_atomic_snapshots",
        })
    return windows


def _window_id(qpc: int, windows: list[dict[str, Any]]) -> str | None:
    for window in windows:
        if window["begin_qpc_exclusive"] < qpc < window["end_qpc_exclusive"]:
            return str(window["id"])
    return None


def _target_read(read_id: str) -> bool:
    return (read_id.startswith("dispatch-target-")
            or read_id.startswith("record-target-")
            or read_id == "resolved-target-stack")


def _receiver_read(read_id: str) -> bool:
    return (read_id.startswith("object-")
            or read_id.startswith("attach-owner")
            or read_id == "dispatch-receiver-rbx")


def summarize_events(events: Iterable[tuple[dict[str, Any], bytes]], *,
                     points: list[str], module_base: int, module_size: int,
                     windows: list[dict[str, Any]]) -> dict[str, Any]:
    slots: dict[str, Counter[int]] = defaultdict(Counter)
    sites: dict[str, dict[str, Any]] = {
        point: {"events": 0, "targets": Counter(), "target_reads": defaultdict(Counter),
                "class_names": Counter(), "class_target_pairs": Counter(),
                "receivers": defaultdict(set),
                "windows": Counter(), "unassigned_boundary_events": 0}
        for point in points if point.startswith(DYNAMIC_PREFIX)
    }
    anchor_events = 0
    for event, blob in events:
        point = event.get("point", "")
        if point.startswith(ANCHOR_PREFIX):
            anchor_events += 1
            for read in event.get("reads", []):
                if read.get("status") == 1 and read.get("id", "").startswith("initialized-slot-"):
                    slots[read["id"]][int(read["value"])] += 1
            continue
        if point not in sites:
            continue
        row = sites[point]
        row["events"] += 1
        window = _window_id(int(event["qpc"]), windows)
        if window is None:
            row["unassigned_boundary_events"] += 1
        else:
            row["windows"][window] += 1
        event_target_values: set[int] = set()
        event_class_names: set[str] = set()
        for read in event.get("reads", []):
            if read.get("status") != 1:
                continue
            rid = str(read["id"])
            if _target_read(rid):
                value = int(read["value"])
                event_target_values.add(value)
                row["target_reads"][rid][value] += 1
            elif rid.startswith("class-name-") and not rid.startswith("class-name-pointer-"):
                name = _class_name(read, blob)
                event_class_names.add(name)
                row["class_names"][name] += 1
            elif _receiver_read(rid):
                row["receivers"][rid].add(int(read["value"]))
        # Multiple independent target reads may intentionally verify the same
        # value in one callback.  Count a target at most once per event here;
        # per-read counts remain available below for exact provenance.
        for value in event_target_values:
            row["targets"][value] += 1
        for name in event_class_names:
            for value in event_target_values:
                row["class_target_pairs"][(name, value)] += 1

    slot_rows = []
    for rid, values in sorted(slots.items()):
        slot_rva = int(rid.rsplit("-", 1)[1], 16)
        slot_rows.append({
            "read_id": rid,
            "slot_rva": slot_rva,
            "observations": sum(values.values()),
            "stable": len(values) == 1,
            "values": [{**_address(value, module_base, module_size), "count": count}
                       for value, count in sorted(values.items())],
        })

    site_rows = []
    for point, row in sites.items():
        event_count = int(row["events"])
        site_rows.append({
            "point": point,
            "events": event_count,
            "observation": ("OBSERVED" if event_count
                            else "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION"),
            "targets": [{**_address(value, module_base, module_size), "count": count}
                        for value, count in sorted(row["targets"].items())],
            "targets_by_read": [
                {"read_id": rid,
                 "values": [{**_address(value, module_base, module_size), "count": count}
                            for value, count in sorted(values.items())]}
                for rid, values in sorted(row["target_reads"].items())],
            "class_names": [{"name": name, "count": count}
                            for name, count in sorted(row["class_names"].items())],
            "class_target_pairs": [
                {"class_name": name, "target": _address(value, module_base, module_size),
                 "count": count}
                for (name, value), count in sorted(row["class_target_pairs"].items())],
            "observed_address_candidates": [
                {"read_id": rid, "unique_addresses": len(values),
                 "addresses": sorted(values)}
                for rid, values in sorted(row["receivers"].items())],
            "action_windows": dict(sorted(row["windows"].items())),
            "unassigned_boundary_events": int(row["unassigned_boundary_events"]),
        })
    return {"anchor_events": anchor_events, "initialized_slots": slot_rows,
            "dynamic_sites": site_rows}


def analyze(session: Path, contract_path: Path, qualified_plan_path: Path,
            output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    session = session.resolve()
    contract = _load(contract_path)
    if contract.get("schema") != "uc.ability-dynamic-dispatch-static-contract.v1":
        raise ValueError("unsupported dynamic-dispatch static contract")
    if contract.get("summary", {}).get("physical_dynamic_probe_sites") != 35:
        raise ValueError("static contract is not the bounded 35-point unit")
    plan = _load(qualified_plan_path)
    compiled = compile_probe_pair(plan, verify_sources=True)

    inspection = inspect_session(session)
    if inspection["errors"] or not inspection["storage_complete"]:
        raise ValueError(f"session storage is incomplete: {inspection['errors']}")
    if inspection["cleanup"] != "STOPPED_CLEAN":
        raise ValueError(f"session cleanup is not clean: {inspection['cleanup']}")
    if any(int(row.get("events", 0)) or int(row.get("read_failures", 0))
           or int(row.get("truncated", 0)) for row in inspection["loss"]):
        raise ValueError("session contains point loss, read failure, or truncation")

    manifest_path = session / "session.manifest"
    manifest, manifest_errors = read_manifest(manifest_path)
    if manifest_errors:
        raise ValueError(f"manifest is invalid: {manifest_errors}")
    activations = [row for row in manifest if row.get("kind") == "plan_activation"
                   and row.get("plan_hash") == compiled.plan_hash]
    if len(activations) != 1:
        raise ValueError("expected one matching plan activation")
    activation = activations[0]
    generation = int(activation["generation"])
    bindings = activation.get("bindings", [])
    bases = {(int(row["module_base"]), int(row["module_size"]), row["module_sha256"])
             for row in bindings}
    if len(bases) != 1:
        raise ValueError("activation does not have one GameAssembly binding identity")
    module_base, module_size, module_sha256 = bases.pop()
    if module_sha256 != contract["sources"]["game-module"]["sha256"]:
        raise ValueError("runtime module differs from static contract")

    coverage = {row["point"]: row for row in manifest
                if row.get("kind") == "coverage" and int(row.get("generation", -1)) == generation}
    points = [row["point"] for row in bindings]
    if set(coverage) != set(points) or not all(row.get("complete") for row in coverage.values()):
        raise ValueError("point coverage is not complete for the activation")
    checkpoints = [row for row in manifest if row.get("kind") == "capture_checkpoint"]
    windows = _checkpoint_windows(checkpoints)

    context = event_dictionary_context(manifest_path, manifest)
    event_rows = []
    for chunk in inspection["chunks"]:
        _, records = decode_chunk_file(session / chunk["file"], dictionary_context=context)
        for _, _, event, blob in records:
            if int(event.get("generation", -1)) == generation:
                event_rows.append((event, blob))
    summary = summarize_events(event_rows, points=points, module_base=module_base,
                               module_size=module_size, windows=windows)
    contract_by_point = {
        f"AbilityDispatch.Dynamic@0x{int(row['physical_probe_rva']):x}/entry": row
        for row in contract["dynamic_dispatch_contracts"]}
    for row in summary["dynamic_sites"]:
        row["static_contract"] = contract_by_point[row["point"]]

    result = {
        "schema": "uc.ability-dynamic-dispatch-runtime-analysis.v1",
        "sources": {"session_manifest": _source(manifest_path),
                    "static_contract": _source(contract_path),
                    "qualified_plan": _source(qualified_plan_path)},
        "session": {"generation": generation, "plan_hash": compiled.plan_hash,
                    "cleanup": inspection["cleanup"], "storage_complete": True,
                    "chunk_count": len(inspection["chunks"]),
                    "event_count": sum(int(row["event_count"]) for row in inspection["chunks"]),
                    "loss_events": 0, "coverage_complete_points": len(coverage)},
        "module": {"name": "GameAssembly.dll", "base": module_base,
                   "size": module_size, "sha256": module_sha256},
        "checkpoint_windows": windows,
        **summary,
    }
    result["summary"] = {
        "initialized_slots_expected": 21,
        "initialized_slots_observed": len(summary["initialized_slots"]),
        "initialized_slots_stable": sum(row["stable"] for row in summary["initialized_slots"]),
        "physical_dynamic_probe_sites": len(summary["dynamic_sites"]),
        "observed_dynamic_probe_sites": sum(row["events"] > 0 for row in summary["dynamic_sites"]),
        "unobserved_dynamic_probe_sites": sum(row["events"] == 0 for row in summary["dynamic_sites"]),
        "logical_dynamic_callsites": contract["summary"]["dynamic_callsites"],
        "semantic_callee_names_assigned": 0,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(result))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", type=Path)
    parser.add_argument("static_contract", type=Path)
    parser.add_argument("qualified_plan", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.session, args.static_contract, args.qualified_plan, args.output)
    except Exception as error:
        write_failure(args.output, "ability_dynamic_dispatch_analyze", error, {
            "session": str(args.session), "static_contract": str(args.static_contract),
            "qualified_plan": str(args.qualified_plan)})
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
