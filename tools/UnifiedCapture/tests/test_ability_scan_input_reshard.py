from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_scan_input_reshard import build


def test_reshard_preserves_targets_and_partitions_unique_types(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_text(
        "schema=test\n"
        "TARGET|slot=0x10|wrapper-rva=0x20\n"
        "TYPE|index=9\nTYPE|index=3\nTYPE|index=9\nTYPE|index=7\n",
        encoding="utf-8",
    )
    report = build(source, 2, tmp_path / "out")
    assert report["target_pairs"] == 1
    assert report["type_indexes"] == 3
    assert report["shards"] == 2
    first = (tmp_path / "out/shard-0000.txt").read_text(encoding="utf-8")
    second = (tmp_path / "out/shard-0001.txt").read_text(encoding="utf-8")
    assert "TYPE|index=3" in first and "TYPE|index=7" in first
    assert "TYPE|index=9" in second
    assert first.count("TARGET|") == second.count("TARGET|") == 1
