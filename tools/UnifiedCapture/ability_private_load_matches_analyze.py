"""Preserve exact positive matches from one bounded private-load owner scan."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ability_slot_owner_scan_analyze import MATCH, SUMMARY
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size, "sha256": file_hash(path)}


def build(scan_input: Path, scan_output: Path, out: Path, catalog_out: Path) -> dict[str, Any]:
    if out.exists() or catalog_out.exists():
        raise FileExistsError("outputs are immutable")
    target_count = sum(line.startswith("TARGET|") for line in
                       scan_input.read_text(encoding="utf-8-sig").splitlines())
    type_count = sum(line.startswith("TYPE|") for line in
                     scan_input.read_text(encoding="utf-8-sig").splitlines())
    lines = scan_output.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    summaries = [SUMMARY.fullmatch(line) for line in lines if line.startswith("SUMMARY|")]
    summaries = [row for row in summaries if row]
    matches = []
    for line_number, line in enumerate(lines, 1):
        match = MATCH.fullmatch(line)
        if not match:
            continue
        matches.append({
            "type_index": int(match.group(1)), "type_token": int(match.group(2), 0),
            "namespace": match.group(3), "class": match.group(4),
            "method_ordinal": int(match.group(5)), "method": match.group(6),
            "method_rva": int(match.group(7), 0), "target_rva": int(match.group(8), 0),
            "method_info": int(match.group(9), 16), "line": line_number,
        })
    unique = {(row["type_index"], row["method_ordinal"], row["method_rva"]): row for row in matches}
    matches = sorted(unique.values(), key=lambda row: (row["target_rva"], row["type_index"], row["method_ordinal"]))
    complete = len(summaries) == 1 and int(summaries[0].group(1)) == type_count
    summary = {
        "target_rvas": target_count, "requested_type_indexes": type_count,
        "exact_positive_matches": len(matches),
        "exact_positive_target_rvas": len(set(row["target_rva"] for row in matches)),
        "scan_complete": complete,
        "reported_processed_types": int(summaries[0].group(1)) if summaries else None,
    }
    artifact = {
        "schema": "uc.ability-private-load-match-analysis.v1",
        "sources": {"scan_input": _source(scan_input), "scan_output": _source(scan_output)},
        "summary": summary,
        "bounded_conclusions": [
            "positive rows are exact method code-RVA joins from the private-loaded game image",
            "an incomplete scan cannot support negative owner conclusions",
            "the scan never attached to or started a game process",
        ],
        "runtime_needed_now": False, "matches": matches,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-private-load-match-analysis.json"
    artifact_path.write_bytes(canonical(artifact))
    labels = {
        (row["type_index"], row["class"], row["namespace"]): f"type-{row['type_index']}"
        for row in matches if row["method"]
    }
    catalog_lines = ["schema=zzz.ability-private-load-runtime-methods.v1|private-load=true"]
    for (type_index, class_name, namespace), label in sorted(labels.items()):
        catalog_lines.append(f"CLASS|label={label}|name={class_name}|namespace={namespace}|type={type_index}")
        for row in matches:
            if row["type_index"] == type_index and row["method"]:
                catalog_lines.append(
                    f"METHOD|label={label}|index={row['method_ordinal']}|name={row['method']}|rva=0x{row['method_rva']:x}")
    catalog_out.parent.mkdir(parents=True, exist_ok=True)
    catalog_out.write_text("\n".join(catalog_lines) + "\n", encoding="utf-8", newline="\n")
    report = {"schema": "uc.ability-private-load-match-analysis-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "method_catalog": {"path": str(catalog_out), "sha256": file_hash(catalog_out)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-input", type=Path, required=True)
    parser.add_argument("--scan-output", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--catalog-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.scan_input.resolve(), args.scan_output.resolve(),
                     args.out.resolve(), args.catalog_out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_private_load_matches_analyze", error, {
            "scan_input": str(args.scan_input), "scan_output": str(args.scan_output),
            "catalog_out": str(args.catalog_out),
        })
        raise


if __name__ == "__main__":
    run_main(main)
