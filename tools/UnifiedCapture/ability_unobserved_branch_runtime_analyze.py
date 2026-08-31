"""Analyze a sealed Ability branch-input capture without inventing predicates."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Iterable

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.probe_pair import compile_probe_pair
from uc.store import (decode_chunk_file, event_dictionary_context,
                      inspect_session, read_manifest)


POINT_PREFIX = "AbilityBranchInput.Predicate@"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


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
            "begin_qpc_exclusive": begin, "end_qpc_exclusive": end,
            "boundary_semantics": "conservative_interior_between_non_atomic_snapshots",
        })
    return windows


def _window_id(qpc: int, windows: list[dict[str, Any]]) -> str | None:
    for window in windows:
        if window["begin_qpc_exclusive"] < qpc < window["end_qpc_exclusive"]:
            return str(window["id"])
    return None


def _required_path_admitted(value: int, contract: dict[str, Any]) -> bool:
    logical = contract["logical_contracts"]
    outcomes = set()
    for row in logical:
        # The selected conditional is immediately after the captured predicate
        # and is preserved in the source join, not inferred from this value.
        required = row["required_branch_outcome_for_original_site"]
        branch = row.get("zero_branch_mnemonic")
        if branch not in ("je", "jne"):
            raise ValueError(f"unsupported zero predicate branch: {branch!r}")
        taken = (value == 0) if branch == "je" else (value != 0)
        outcomes.add(taken if required == "TAKEN" else not taken)
    if len(outcomes) != 1:
        raise ValueError("coalesced source points disagree on required zero-predicate outcome")
    return outcomes.pop()


def summarize_events(events: Iterable[tuple[dict[str, Any], bytes]], *,
                     contracts: list[dict[str, Any]], windows: list[dict[str, Any]]) -> dict[str, Any]:
    by_point = {
        f"{POINT_PREFIX}0x{int(row['physical_predicate_rva']):x}/entry": row
        for row in contracts
    }
    states = {
        point: {"events": 0, "read_values": defaultdict(Counter),
                "read_statuses": defaultdict(Counter), "windows": Counter(),
                "required_admitted": 0, "required_rejected": 0,
                "control_matches": 0, "control_mismatches": 0,
                "control_unavailable": 0, "boundary_events": 0}
        for point in by_point
    }
    for event, _blob in events:
        point = event.get("point", "")
        if point not in states:
            continue
        state = states[point]
        state["events"] += 1
        window = _window_id(int(event["qpc"]), windows)
        if window is None:
            state["boundary_events"] += 1
        else:
            state["windows"][window] += 1
        successful = {}
        for read in event.get("reads", []):
            read_id = str(read["id"])
            status = int(read.get("status", 0))
            state["read_statuses"][read_id][status] += 1
            if status == 1 and "value" in read:
                value = int(read["value"])
                successful[read_id] = value
                state["read_values"][read_id][value] += 1
        contract = by_point[point]
        raw_ids = {row["raw_tested_value"]["read_id"]
                   for row in contract["logical_contracts"]}
        if len(raw_ids) != 1:
            raise ValueError("coalesced point has different raw tested-value reads")
        raw_id = raw_ids.pop()
        if raw_id in successful:
            if _required_path_admitted(successful[raw_id], contract):
                state["required_admitted"] += 1
            else:
                state["required_rejected"] += 1
        control_ids = [read_id for read_id in successful
                       if read_id.startswith("exact-field-")
                       or read_id.startswith("unnamed-this-offset+")
                       or read_id.startswith("tested-stack-slot+")]
        if raw_id not in successful or not control_ids:
            state["control_unavailable"] += 1
        else:
            control = successful[control_ids[-1]]
            if successful[raw_id] == control:
                state["control_matches"] += 1
            else:
                state["control_mismatches"] += 1

    rows = []
    for point, contract in by_point.items():
        state = states[point]
        rows.append({
            "point": point, "events": int(state["events"]),
            "observation": ("OBSERVED" if state["events"]
                            else "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION"),
            "represented_source_points": contract["represented_source_points"],
            "logical_contracts": contract["logical_contracts"],
            "required_path_admitted_events": int(state["required_admitted"]),
            "required_path_rejected_events": int(state["required_rejected"]),
            "control_consistency": {
                "matches": int(state["control_matches"]),
                "mismatches": int(state["control_mismatches"]),
                "unavailable_events": int(state["control_unavailable"]),
            },
            "read_values": [
                {"read_id": read_id,
                 "values": [{"value": value, "count": count}
                            for value, count in sorted(values.items())],
                 "statuses": [{"status": status, "count": count}
                              for status, count in sorted(
                                  state["read_statuses"][read_id].items())]}
                for read_id, values in sorted(state["read_values"].items())
            ],
            "read_statuses_without_values": [
                {"read_id": read_id,
                 "statuses": [{"status": status, "count": count}
                              for status, count in sorted(statuses.items())]}
                for read_id, statuses in sorted(state["read_statuses"].items())
                if read_id not in state["read_values"]
            ],
            "checkpoint_windows": dict(sorted(state["windows"].items())),
            "unassigned_boundary_events": int(state["boundary_events"]),
            "semantic_gameplay_predicate_assigned": False,
        })
    return {"predicate_sites": rows}


def analyze(session: Path, contract_path: Path, qualified_plan_path: Path,
            output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    session = session.resolve()
    contract = _load(contract_path)
    if contract.get("schema") != "uc.ability-unobserved-branch-runtime-contract.v1":
        raise ValueError("unsupported branch runtime contract")
    if contract.get("summary", {}).get("logical_source_sites") != 14:
        raise ValueError("static contract is not the bounded 14-site unit")
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
    module_rows = {(int(row["module_base"]), int(row["module_size"]),
                    row["module_sha256"]) for row in bindings}
    if len(module_rows) != 1:
        raise ValueError("activation does not have one GameAssembly binding identity")
    module_base, module_size, module_sha256 = module_rows.pop()
    if module_sha256 != contract["sources"]["game-module"]["sha256"]:
        raise ValueError("runtime module differs from static contract")
    coverage = {row["point"]: row for row in manifest
                if row.get("kind") == "coverage" and int(row.get("generation", -1)) == generation}
    points = [row["point"] for row in bindings]
    if set(coverage) != set(points) or not all(row.get("complete") for row in coverage.values()):
        raise ValueError("point coverage is not complete for the activation")
    windows = _checkpoint_windows(
        [row for row in manifest if row.get("kind") == "capture_checkpoint"])
    context = event_dictionary_context(manifest_path, manifest)
    event_rows = []
    for chunk in inspection["chunks"]:
        _, records = decode_chunk_file(session / chunk["file"], dictionary_context=context)
        for _, _, event, blob in records:
            if int(event.get("generation", -1)) == generation:
                event_rows.append((event, blob))
    summary = summarize_events(
        event_rows, contracts=contract["physical_predicate_contracts"], windows=windows)
    result = {
        "schema": "uc.ability-unobserved-branch-runtime-analysis.v1",
        "sources": {"session_manifest": _source(manifest_path),
                    "static_contract": _source(contract_path),
                    "qualified_plan": _source(qualified_plan_path)},
        "session": {"generation": generation, "plan_hash": compiled.plan_hash,
                    "cleanup": inspection["cleanup"], "storage_complete": True,
                    "chunk_count": len(inspection["chunks"]),
                    "event_count": sum(int(row["event_count"])
                                       for row in inspection["chunks"]),
                    "loss_events": 0, "coverage_complete_points": len(coverage)},
        "module": {"name": "GameAssembly.dll", "base": module_base,
                   "size": module_size, "sha256": module_sha256},
        "checkpoint_windows": windows, **summary,
    }
    result["summary"] = {
        "logical_source_sites": contract["summary"]["logical_source_sites"],
        "physical_predicate_sites": len(summary["predicate_sites"]),
        "observed_predicate_sites": sum(row["events"] > 0
                                        for row in summary["predicate_sites"]),
        "unobserved_predicate_sites": sum(row["events"] == 0
                                          for row in summary["predicate_sites"]),
        "required_path_admitted_events": sum(row["required_path_admitted_events"]
                                             for row in summary["predicate_sites"]),
        "required_path_rejected_events": sum(row["required_path_rejected_events"]
                                             for row in summary["predicate_sites"]),
        "control_mismatches": sum(row["control_consistency"]["mismatches"]
                                  for row in summary["predicate_sites"]),
        "semantic_gameplay_predicates_assigned": 0,
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
        result = analyze(args.session, args.static_contract,
                         args.qualified_plan, args.output)
    except Exception as error:
        write_failure(args.output, "ability_unobserved_branch_runtime_analyze", error, {
            "session": str(args.session), "static_contract": str(args.static_contract),
            "qualified_plan": str(args.qualified_plan)})
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
