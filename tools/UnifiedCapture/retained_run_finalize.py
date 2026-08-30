"""Finalize one clean retained run into acceptance, coverage and caller inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from entry_analyze import analyze_run
from evidence_stream_summary import summarize
from retained_caller_inventory import run as inventory_callers
from uc.cli import run_main
from uc.model import canonical, file_hash


def run(run_path: Path, output: Path) -> dict[str, Any]:
    run_path, output = run_path.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    output.mkdir(parents=True)
    acceptance_dir = output / "acceptance"
    acceptance = analyze_run(run_path, acceptance_dir)
    coverage_path = output / "streaming-summary.json"
    coverage = summarize(run_path, coverage_path)
    inventory_dir = output / "caller-inventory"
    inventory = inventory_callers(acceptance_dir / "entry-acceptance.json", inventory_dir)
    ready = acceptance.get("accepted") is True and coverage.get("store_clean") is True \
        and inventory.get("all_retained_points_complete") is True
    report = {
        "schema": "uc.retained-run-finalization.v1",
        "run": str(run_path),
        "ready_for_exact_selection": ready,
        "acceptance": {"path": str(acceptance_dir / "entry-acceptance.json"),
                       "sha256": file_hash(acceptance_dir / "entry-acceptance.json"),
                       "accepted": acceptance.get("accepted"),
                       "summary": acceptance.get("summary", {})},
        "coverage": {"path": str(coverage_path), "sha256": file_hash(coverage_path),
                     "store_clean": coverage.get("store_clean"),
                     "totals": coverage.get("totals", {})},
        "caller_inventory": {
            "path": str(inventory_dir / "retained-caller-inventory.json"),
            "sha256": file_hash(inventory_dir / "retained-caller-inventory.json"),
            "all_retained_points_complete": inventory.get("all_retained_points_complete"),
            "totals": inventory.get("totals", {}),
        },
        "selection_performed": False,
        "semantic_identity_inferred": False,
    }
    report_path = output / "report.json"
    report_path.write_bytes(canonical(report))
    print(json.dumps({"report": str(report_path),
                      "ready_for_exact_selection": ready,
                      "acceptance_summary": acceptance.get("summary", {}),
                      "caller_totals": inventory.get("totals", {})}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run_main(run, args.run, args.out)
