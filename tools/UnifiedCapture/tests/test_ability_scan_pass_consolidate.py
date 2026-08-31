from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_scan_pass_consolidate import build
from uc.model import file_hash


def _make_pass(root: Path, name: str, groups: list[tuple[list[int], str]]) -> tuple[Path, Path]:
    shard_dir = root / f"{name}-shards"
    shard_dir.mkdir()
    shards = []
    analysis_shards = []
    all_types = set()
    for ordinal, (types, status) in enumerate(groups):
        path = shard_dir / f"shard-{ordinal:04d}.txt"
        path.write_text("TARGET|slot=0x10|wrapper-rva=0x10\n" +
                        "".join(f"TYPE|index={value}\n" for value in types), encoding="utf-8")
        all_types.update(types)
        shards.append({"ordinal": ordinal, "path": str(path), "count": len(types),
                       "sha256": file_hash(path)})
        analysis_shards.append({"ordinal": ordinal, "status": status,
                                "reported_processed_types": len(types) if status == "COMPLETE" else None})
    manifest = root / f"{name}-manifest.json"
    manifest.write_text(json.dumps({"schema": "zzz.ability-scan-input-shards.v1",
                                    "type_indexes": len(all_types), "target_pairs": 1,
                                    "shards": shards}), encoding="utf-8")
    analysis = root / f"{name}-analysis.json"
    analysis.write_text(json.dumps({"schema": "uc.ability-slot-owner-scan-analysis.v1",
                                    "sources": {"manifest": {"sha256": file_hash(manifest)}},
                                    "shards": analysis_shards, "matches": []}), encoding="utf-8")
    return manifest, analysis


def test_multipass_proves_exact_base_coverage(tmp_path: Path) -> None:
    base = _make_pass(tmp_path, "base", [([1, 2], "COMPLETE"), ([3, 4], "INCOMPLETE")])
    retry = _make_pass(tmp_path, "retry", [([3], "COMPLETE"), ([4], "COMPLETE")])
    out = tmp_path / "out"
    report = build([base, retry], out)
    assert report["summary"] == {
        "target_rvas": 1, "requested_types": 4, "covered_types": 4,
        "uncovered_types": 0, "exact_positive_matches": 0, "scan_complete": True,
    }
    artifact = json.loads((out / "ability-private-load-multipass-scan.json").read_text())
    assert artifact["uncovered_type_indexes"] == []


def test_multipass_keeps_uncovered_types_explicit(tmp_path: Path) -> None:
    base = _make_pass(tmp_path, "base", [([1], "COMPLETE"), ([2, 3], "INCOMPLETE")])
    retry = _make_pass(tmp_path, "retry", [([2], "COMPLETE")])
    out = tmp_path / "out"
    report = build([base, retry], out)
    assert report["summary"]["scan_complete"] is False
    assert json.loads((out / "ability-private-load-multipass-scan.json").read_text())["uncovered_type_indexes"] == [3]
