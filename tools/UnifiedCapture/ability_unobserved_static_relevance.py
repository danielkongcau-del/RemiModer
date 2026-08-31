"""Join unobserved dynamic sites to authoritative Remielle asset coverage."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def build(runtime_path: Path, coverage_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    runtime = _load(runtime_path)
    coverage = _load(coverage_path)
    if runtime.get("schema") != "uc.ability-dynamic-dispatch-runtime-analysis.v1":
        raise ValueError("unsupported runtime analysis")
    if coverage.get("schema") != "uc.ability-executor-coverage-ledger.v1":
        raise ValueError("unsupported Ability coverage ledger")
    session = runtime.get("session", {})
    if (session.get("cleanup") != "STOPPED_CLEAN" or session.get("loss_events") != 0
            or not session.get("storage_complete")):
        raise ValueError("runtime session is not clean and complete")

    coverage_by_type = {row["serialized_type"]: row for row in coverage["types"]}
    rows = []
    classifications: Counter[str] = Counter()
    unobserved_sites = [row for row in runtime["dynamic_sites"]
                        if row.get("observation") == "NOT_OBSERVED_IN_COMPLETE_COVERED_SESSION"]
    for site in unobserved_sites:
        represented = site["static_contract"]["represented_callsites"]
        if not represented:
            raise ValueError(f"unobserved site has no represented callsite: {site['point']}")
        for callsite in represented:
            caller_type = callsite["caller_type"]
            type_row = coverage_by_type.get(caller_type)
            if type_row is None:
                raise ValueError(f"caller type absent from Ability coverage: {caller_type}")
            occurrences = int(type_row["occurrences"])
            classification = ("STATIC_INITIALIZER_TIMING_SITE" if callsite["caller_method"] == ".cctor"
                              else "RUNTIME_CONDITIONAL_OR_UNEXERCISED_PATH")
            classifications[classification] += 1
            rows.append({
                "point": site["point"],
                "physical_probe_rva": int(site["static_contract"]["physical_probe_rva"]),
                "site_rva": int(callsite["site_rva"]),
                "caller_type": caller_type,
                "caller_method": callsite["caller_method"],
                "dispatch_form": callsite["dispatch_form"],
                "observation": site["observation"],
                "static_relevance_class": classification,
                "remielle_origin_occurrences": occurrences,
                "remielle_origin_abilities": type_row["abilities"],
                "coverage_inventory_pointer": type_row["inventory_pointer"],
                "positions_complete": bool(type_row["positions_complete"]),
                "local_dataflow": callsite["local_dataflow"],
            })

    summary = {
        "unobserved_physical_probe_sites": len(unobserved_sites),
        "represented_unobserved_callsites": len(rows),
        "callsites_with_remielle_origin_asset_occurrences": sum(
            row["remielle_origin_occurrences"] > 0 for row in rows),
        "unique_caller_types": len({row["caller_type"] for row in rows}),
        "classification_counts": dict(sorted(classifications.items())),
    }
    if summary["unobserved_physical_probe_sites"] != runtime["summary"]["unobserved_dynamic_probe_sites"]:
        raise ValueError("runtime unobserved-site count is internally inconsistent")
    artifact = {
        "schema": "uc.ability-unobserved-static-relevance.v1",
        "sources": {"runtime_analysis": _source(runtime_path),
                    "ability_coverage": _source(coverage_path)},
        "summary": summary,
        "bounded_conclusions": [
            "all listed sites were not observed in a clean complete covered runtime session",
            "an asset occurrence proves Remielle Origin static relevance, not execution in the captured scenario",
            "the static-initializer site is timing-sensitive and is not a gameplay repetition gap",
            "runtime-conditional classification does not assign an unproven branch predicate or player action",
            "a future runtime unit is justified only after static branch analysis identifies a distinct reachable condition",
        ],
        "runtime_needed_now": False,
        "sites": sorted(rows, key=lambda row: (row["site_rva"], row["caller_type"])),
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-unobserved-static-relevance.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-unobserved-static-relevance-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.runtime.resolve(), args.coverage.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_unobserved_static_relevance", error,
                      {"runtime": str(args.runtime), "coverage": str(args.coverage)})
        raise


if __name__ == "__main__":
    run_main(main)
