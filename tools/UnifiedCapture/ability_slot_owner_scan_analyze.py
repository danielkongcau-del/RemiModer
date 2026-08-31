"""Validate and consolidate bounded private-load slot-owner scan results."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_MANIFEST = ROOT / "extracted/analysis/ability-slot-owner-scan-shards-20260831-v1/manifest.json"
DEFAULT_RESULTS = ROOT / "extracted/analysis/ability-slot-owner-scan-results-20260831-v1"
MATCH = re.compile(
    r"^MATCH\|type=(\d+)\|token=(0x[0-9a-fA-F]+)\|namespace=([^|]*)\|class=([^|]+)"
    r"\|index=(\d+)\|name=([^|]*)\|rva=(0x[0-9a-fA-F]+)\|slot=(0x[0-9a-fA-F]+)"
    r"\|method-info=([0-9A-Fa-f]+)$")
SUMMARY = re.compile(r"^SUMMARY\|processed-types=(\d+)\|matches=(\d+)$")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size, "sha256": file_hash(path)}


def build(manifest_path: Path, results_dir: Path, out: Path, catalog_out: Path) -> dict[str, Any]:
    if out.exists() or catalog_out.exists():
        raise FileExistsError("outputs are immutable")
    manifest = _load(manifest_path)
    if manifest.get("schema") not in (
            "zzz.ability-slot-owner-scan-shards.v1",
            "zzz.ability-scan-input-shards.v1"):
        raise ValueError("unsupported scan shard manifest")
    shards = []
    matches = []
    for shard in manifest["shards"]:
        path = results_dir / (Path(shard["path"]).stem + ".out.txt")
        if not path.is_file():
            shards.append({**shard, "status": "MISSING_OUTPUT", "output": None})
            continue
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        summaries = [SUMMARY.fullmatch(line) for line in lines if line.startswith("SUMMARY|")]
        summaries = [row for row in summaries if row]
        status = "COMPLETE" if len(summaries) == 1 and int(summaries[0].group(1)) == shard["count"] else "INCOMPLETE"
        shards.append({**shard, "status": status, "output": _source(path),
                       "reported_processed_types": int(summaries[0].group(1)) if summaries else None})
        for line_number, line in enumerate(lines, 1):
            match = MATCH.fullmatch(line)
            if not match:
                continue
            matches.append({
                "type_index": int(match.group(1)), "type_token": int(match.group(2), 0),
                "namespace": match.group(3), "class": match.group(4),
                "method_ordinal": int(match.group(5)), "method": match.group(6),
                "method_rva": int(match.group(7), 0), "slot_rva": int(match.group(8), 0),
                "method_info": int(match.group(9), 16), "source": str(path.resolve()),
                "line": line_number, "source_shard_status": status,
            })
    unique = {}
    for row in matches:
        key = (row["type_index"], row["method_ordinal"], row["method_rva"], row["slot_rva"])
        unique[key] = row
    matches = sorted(unique.values(), key=lambda row: (row["slot_rva"], row["type_index"], row["method_ordinal"]))
    complete = sum(row["status"] == "COMPLETE" for row in shards)
    summary = {
        "shards": len(shards), "complete_shards": complete,
        "incomplete_or_missing_shards": len(shards) - complete,
        "exact_positive_matches": len(matches),
        "exact_positive_slots": len(set(row["slot_rva"] for row in matches)),
        "scan_complete": complete == len(shards),
    }
    artifact = {
        "schema": "uc.ability-slot-owner-scan-analysis.v1",
        "sources": {"manifest": _source(manifest_path)},
        "summary": summary,
        "bounded_conclusions": [
            "each MATCH is an exact private-load method-code RVA to generated wrapper-slot join",
            "a MATCH remains positive evidence even when a later type terminated the same shard",
            "incomplete shards forbid a complete negative slot-owner conclusion",
            "the scan never attached to or started a game process",
        ],
        "runtime_needed_now": False,
        "matches": matches, "shards": shards,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-slot-owner-scan-analysis.json"
    artifact_path.write_bytes(canonical(artifact))
    labels = {}
    for row in matches:
        if not row["method"]:
            continue
        labels.setdefault((row["type_index"], row["class"], row["namespace"]), f"type-{row['type_index']}")
    lines = ["schema=zzz.ability-slot-owner-runtime-methods.v1|private-load=true"]
    for (type_index, class_name, namespace), label in sorted(labels.items()):
        lines.append(f"CLASS|label={label}|name={class_name}|namespace={namespace}|type={type_index}")
        for row in matches:
            if row["type_index"] == type_index and row["method"]:
                lines.append(
                    f"METHOD|label={label}|index={row['method_ordinal']}|name={row['method']}|rva=0x{row['method_rva']:x}")
    catalog_out.parent.mkdir(parents=True, exist_ok=True)
    catalog_out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    report = {
        "schema": "uc.ability-slot-owner-scan-analysis-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "method_catalog": {"path": str(catalog_out), "sha256": file_hash(catalog_out)},
        "summary": summary, "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--catalog-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.manifest.resolve(), args.results.resolve(), args.out.resolve(), args.catalog_out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_slot_owner_scan_analyze", error, {
            "manifest": str(args.manifest), "results": str(args.results),
            "catalog_out": str(args.catalog_out),
        })
        raise


if __name__ == "__main__":
    run_main(main)
