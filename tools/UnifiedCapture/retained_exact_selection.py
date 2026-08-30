"""Select every mechanically eligible retained caller without semantic inference."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def run(inventory_path: Path, output: Path) -> dict[str, Any]:
    inventory_path, output = inventory_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8-sig"))
    if inventory.get("schema") != "uc.retained-caller-inventory.v1":
        raise ValueError("retained caller inventory schema")
    if inventory.get("session_clean") is not True or inventory.get("all_retained_points_complete") is not True:
        raise ValueError("retained caller inventory is not complete and clean")
    points = []
    rejected = []
    for row in inventory.get("points", []):
        callers = []
        for candidate in row.get("candidates", []):
            if candidate.get("exact_promotion_eligible") is not True:
                rejected.append({"point": row.get("source_plan_point"),
                                 "module": candidate.get("module"), "return_rva": candidate.get("return_rva"),
                                 "reasons": candidate.get("ineligibility_reasons", [])})
                continue
            if not isinstance(candidate.get("module"), str) or type(candidate.get("return_rva")) is not int:
                raise ValueError("eligible candidate lacks module-relative identity")
            callers.append({"module": candidate["module"], "return_rva": candidate["return_rva"],
                            "evidence": []})
        if callers:
            points.append({"point": row["source_plan_point"],
                           "callers": sorted(callers, key=lambda item: (item["module"], item["return_rva"]))})
    if not points:
        raise ValueError("inventory contains no exact-promotion-eligible caller")
    selection = {
        "schema": "uc.exact-caller-selection.v1", "points": points,
        "authority": "scope-only-not-game-evidence",
        "selection_policy": "all mechanically eligible callers from one clean complete retained inventory",
        "source_inventory": {"path": str(inventory_path), "sha256": file_hash(inventory_path)},
    }
    output.mkdir(parents=True)
    artifact = output / "exact-caller-selection.json"
    artifact.write_bytes(canonical(selection))
    report = {
        "schema": "uc.retained-exact-selection-report.v1",
        "selection": {"path": str(artifact), "sha256": file_hash(artifact)},
        "points": len(points), "callers": sum(len(row["callers"]) for row in points),
        "ineligible_not_selected": len(rejected), "rejected": rejected,
        "semantic_identity_inferred": False,
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.inventory, args.out)
