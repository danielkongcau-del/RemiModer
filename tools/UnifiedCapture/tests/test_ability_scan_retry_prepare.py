from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_scan_retry_prepare import build


def test_retry_contains_only_incomplete_shard_types(tmp_path: Path) -> None:
    shards = tmp_path / "shards"
    results = tmp_path / "results"
    shards.mkdir()
    results.mkdir()
    rows = []
    for ordinal, types in enumerate(([1, 2], [3, 4])):
        path = shards / f"shard-{ordinal:04d}.txt"
        path.write_text("TARGET|slot=0x10|wrapper-rva=0x10\n" +
                        "".join(f"TYPE|index={x}\n" for x in types), encoding="utf-8")
        rows.append({"ordinal": ordinal, "path": str(path), "count": len(types)})
    (results / "shard-0000.out.txt").write_text(
        "SUMMARY|processed-types=2|matches=0\n", encoding="utf-8")
    (results / "shard-0001.out.txt").write_text("", encoding="utf-8")
    manifest = shards / "manifest.json"
    manifest.write_text(json.dumps({"shards": rows}), encoding="utf-8")
    out = tmp_path / "retry.txt"
    report = build(manifest, results, out)
    text = out.read_text(encoding="utf-8")
    assert report["incomplete_shards"] == 1
    assert report["type_indexes"] == 2
    assert "TYPE|index=1" not in text
    assert "TYPE|index=3" in text and "TYPE|index=4" in text
