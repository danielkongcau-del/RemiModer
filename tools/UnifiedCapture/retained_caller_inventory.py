"""Build an immutable, non-selecting inventory from retained caller evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def run(acceptance_path: Path, output: Path) -> dict[str, Any]:
    acceptance_path, output = acceptance_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    acceptance = _load(acceptance_path)
    if acceptance.get("schema") not in (
            "uc.entry-evidence-acceptance.v1", "uc.entry-evidence-acceptance.v2"):
        raise ValueError("unsupported entry acceptance schema")
    inspection = acceptance.get("session", {}).get("inspection", {})
    session_clean = inspection.get("storage_complete") is True \
        and inspection.get("cleanup") == "STOPPED_CLEAN" \
        and not inspection.get("errors")
    rows = []
    all_complete = session_clean
    for point in acceptance.get("points", []):
        retention = point.get("retention_generation")
        if not retention:
            continue
        key_rows = retention.get("keys", [])
        keys: dict[int, dict[str, Any]] = {}
        for key in key_rows:
            address = int(key["entry_return_address"])
            row = keys.setdefault(address, {"count": 0, "full_records_persisted": 0,
                "first_qpc": key.get("first_qpc"), "last_qpc": key.get("last_qpc"), "composite_key_count": 0})
            row["count"] += int(key.get("count", 0))
            row["full_records_persisted"] += int(key.get("full_records_persisted", 0))
            row["composite_key_count"] += 1
            if isinstance(key.get("first_qpc"), int):
                row["first_qpc"] = min(value for value in (row.get("first_qpc"), key["first_qpc"]) if isinstance(value, int))
            if isinstance(key.get("last_qpc"), int):
                row["last_qpc"] = max(value for value in (row.get("last_qpc"), key["last_qpc"]) if isinstance(value, int))
        callers = {int(row["return_address"]): row
                   for row in point.get("runtime_caller_evidence", [])
                   if isinstance(row.get("return_address"), int)}
        missing_samples = sorted(address for address, row in keys.items()
                                 if address not in callers or row["full_records_persisted"] < row["composite_key_count"])
        count_total = sum(int(row.get("count", 0)) for row in key_rows)
        complete = retention.get("complete_for_caller_counts") is True \
            and not missing_samples and count_total == int(retention.get("callbacks", -1))
        all_complete &= complete
        candidates = []
        for address in sorted(keys):
            key, caller = keys[address], callers.get(address, {})
            reasons = []
            if key.get("full_records_persisted", 0) < 1:
                reasons.append("NO_PERSISTED_REPRESENTATIVE")
            if caller.get("module_membership") != "INSIDE_BOUND_MODULE" \
                    or not isinstance(caller.get("return_rva"), int) \
                    or not caller.get("module"):
                reasons.append("NO_BOUND_MODULE_RELATIVE_ADDRESS")
            if caller.get("callsite_status") != "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL":
                reasons.append("RETURN_PREDECESSOR_NOT_PROVEN_CALL")
            candidates.append({
                "entry_return_address": address,
                "callbacks": int(key.get("count", 0)),
                "first_qpc": key.get("first_qpc"), "last_qpc": key.get("last_qpc"),
                "full_records_persisted": int(key.get("full_records_persisted", 0)),
                "aggregate_key_count": int(key.get("composite_key_count", 1)),
                "module": caller.get("module"), "return_rva": caller.get("return_rva"),
                "caller_runtime_function": caller.get("caller_runtime_function"),
                "callsite_rva": caller.get("callsite_rva"),
                "call_kind": caller.get("call_kind"),
                "representative_event_id": caller.get("representative_event_id"),
                "exact_promotion_eligible": not reasons,
                "ineligibility_reasons": reasons,
                "selection_row_template": ({"module": caller["module"],
                    "return_rva": caller["return_rva"], "evidence": []} if not reasons else None),
            })
        rows.append({
            "point": point["point"],
            "source_plan_point": point["point"].removesuffix("/entry"),
            "callbacks": int(retention.get("callbacks", 0)),
            "classified_callers": len(keys),
            "count_sum": count_total,
            "complete_for_caller_counts": complete,
            "missing_representative_addresses": missing_samples,
            "candidates": candidates,
        })
    if not rows:
        raise ValueError("acceptance contains no retained caller summaries")
    result = {
        "schema": "uc.retained-caller-inventory.v1",
        "source": {"entry_acceptance": {"path": str(acceptance_path),
                                          "sha256": file_hash(acceptance_path)}},
        "session_clean": session_clean,
        "all_retained_points_complete": all_complete,
        "points": rows,
        "totals": {
            "retained_points": len(rows),
            "classified_callers": sum(row["classified_callers"] for row in rows),
            "callbacks": sum(row["callbacks"] for row in rows),
            "exact_promotion_eligible": sum(candidate["exact_promotion_eligible"]
                for row in rows for candidate in row["candidates"]),
        },
        "authority": {
            "inventory": "mechanically-derived-from-retained-session",
            "selection": "NOT_PERFORMED",
            "semantic_identity": "NOT_INFERRED",
        },
    }
    output.mkdir(parents=True)
    artifact = output / "retained-caller-inventory.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.retained-caller-inventory-report.v1",
              "artifact": {"path": str(artifact), "sha256": file_hash(artifact)},
              "session_clean": session_clean,
              "all_retained_points_complete": all_complete, **result["totals"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.acceptance, args.out)
