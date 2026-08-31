"""Consolidate private-load scan passes into a bounded coverage proof."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": file_hash(path),
    }


def _read_shard(path: Path, expected_hash: str, expected_count: int) -> tuple[set[str], set[int]]:
    if file_hash(path) != expected_hash:
        raise ValueError(f"shard hash mismatch: {path}")
    targets: set[str] = set()
    types: set[int] = set()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("TARGET|"):
            targets.add(line)
        elif line.startswith("TYPE|index="):
            types.add(int(line.split("=", 1)[1]))
    if len(types) != expected_count:
        raise ValueError(f"shard type count mismatch: {path}")
    if not targets:
        raise ValueError(f"shard contains no targets: {path}")
    return targets, types


def build(passes: list[tuple[Path, Path]], out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    if len(passes) < 2:
        raise ValueError("at least a base pass and one recovery pass are required")

    target_set: set[str] | None = None
    base_types: set[int] | None = None
    covered_types: set[int] = set()
    pass_rows: list[dict[str, Any]] = []
    unique_matches: dict[tuple[int, int, int, int], dict[str, Any]] = {}

    for pass_ordinal, (manifest_path, analysis_path) in enumerate(passes):
        manifest = _load(manifest_path)
        analysis = _load(analysis_path)
        if manifest.get("schema") != "zzz.ability-scan-input-shards.v1":
            raise ValueError(f"unsupported manifest schema: {manifest_path}")
        if analysis.get("schema") != "uc.ability-slot-owner-scan-analysis.v1":
            raise ValueError(f"unsupported analysis schema: {analysis_path}")
        analysis_manifest = analysis.get("sources", {}).get("manifest", {})
        if analysis_manifest.get("sha256") != file_hash(manifest_path):
            raise ValueError(f"analysis does not bind the supplied manifest: {analysis_path}")

        analyzed_by_ordinal = {int(row["ordinal"]): row for row in analysis["shards"]}
        if len(analyzed_by_ordinal) != len(manifest["shards"]):
            raise ValueError(f"analysis shard cardinality mismatch: {analysis_path}")
        pass_types: set[int] = set()
        pass_covered: set[int] = set()
        pass_targets: set[str] | None = None
        complete_shards = 0
        for shard in manifest["shards"]:
            ordinal = int(shard["ordinal"])
            analyzed = analyzed_by_ordinal.get(ordinal)
            if analyzed is None:
                raise ValueError(f"analysis lacks shard {ordinal}: {analysis_path}")
            shard_path = Path(shard["path"])
            targets, types = _read_shard(shard_path, shard["sha256"], int(shard["count"]))
            if pass_targets is None:
                pass_targets = targets
            elif targets != pass_targets:
                raise ValueError(f"target set differs within pass: {shard_path}")
            if pass_types.intersection(types):
                raise ValueError(f"duplicate type indexes within pass: {shard_path}")
            pass_types.update(types)
            if analyzed.get("status") == "COMPLETE":
                if analyzed.get("reported_processed_types") != len(types):
                    raise ValueError(f"false COMPLETE shard: {analysis_path}#{ordinal}")
                pass_covered.update(types)
                complete_shards += 1

        if len(pass_types) != int(manifest["type_indexes"]):
            raise ValueError(f"manifest type cardinality mismatch: {manifest_path}")
        if len(pass_targets or ()) != int(manifest["target_pairs"]):
            raise ValueError(f"manifest target cardinality mismatch: {manifest_path}")
        if target_set is None:
            target_set = pass_targets
            base_types = pass_types
        else:
            if pass_targets != target_set:
                raise ValueError(f"target set differs between passes: {manifest_path}")
            if not pass_types.issubset(base_types or set()):
                raise ValueError(f"recovery pass contains types outside base pass: {manifest_path}")

        covered_types.update(pass_covered)
        for row in analysis.get("matches", []):
            key = (int(row["type_index"]), int(row["method_ordinal"]),
                   int(row["method_rva"]), int(row["slot_rva"]))
            unique_matches[key] = {**row, "observed_in_pass": pass_ordinal}
        pass_rows.append({
            "ordinal": pass_ordinal,
            "manifest": _source(manifest_path),
            "analysis": _source(analysis_path),
            "requested_types": len(pass_types),
            "covered_types": len(pass_covered),
            "shards": len(manifest["shards"]),
            "complete_shards": complete_shards,
        })

    assert base_types is not None and target_set is not None
    uncovered = sorted(base_types - covered_types)
    extra_covered = sorted(covered_types - base_types)
    if extra_covered:
        raise ValueError("covered set contains types outside the base pass")
    matches = sorted(unique_matches.values(),
                     key=lambda row: (row["slot_rva"], row["type_index"], row["method_ordinal"]))
    scan_complete = not uncovered
    summary = {
        "target_rvas": len(target_set),
        "requested_types": len(base_types),
        "covered_types": len(covered_types),
        "uncovered_types": len(uncovered),
        "exact_positive_matches": len(matches),
        "scan_complete": scan_complete,
    }
    artifact = {
        "schema": "uc.ability-private-load-multipass-scan.v1",
        "summary": summary,
        "targets": sorted(target_set),
        "passes": pass_rows,
        "uncovered_type_indexes": uncovered,
        "matches": matches,
        "bounded_conclusions": [
            "coverage is the exact union of COMPLETE shard type sets, verified against the base-pass type set",
            "the scan used a private-loaded GameAssembly image and never attached to or started the game",
            ("no exact MethodInfo code-RVA owner was observed for the target RVAs among all base-pass "
             "class-list type indexes") if scan_complete and not matches else
            "the result does not establish a complete negative owner conclusion",
            "the negative result does not identify native, generated, shared, or otherwise uncatalogued code semantics",
        ],
        "runtime_needed_now": False,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-private-load-multipass-scan.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {
        "schema": "uc.ability-private-load-multipass-scan-report.v1",
        "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
        "summary": summary,
        "runtime_needed_now": False,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pass", dest="passes", action="append", nargs=2,
                        metavar=("MANIFEST", "ANALYSIS"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    paths = [(Path(manifest).resolve(), Path(analysis).resolve())
             for manifest, analysis in args.passes]
    try:
        return build(paths, args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_scan_pass_consolidate", error,
                      {"passes": [[str(a), str(b)] for a, b in paths]})
        raise


if __name__ == "__main__":
    run_main(main)
