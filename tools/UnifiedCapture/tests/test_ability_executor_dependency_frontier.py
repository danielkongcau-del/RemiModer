from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ability_executor_dependency_frontier import _catalog, _metadata_annotation, _stratum


def test_catalog_preserves_exact_rva_identity_and_source_line(tmp_path: Path) -> None:
    source = tmp_path / "methods.txt"
    source.write_text(
        "CLASS|7|0x02000007|Game.Ability|Executor|1|raw\n"
        "METHOD|7|0|Run|0x1234|raw|return=<none>.Void|params=0\n",
        encoding="utf-8",
    )
    catalog = _catalog(source)
    assert set(catalog) == {0x1234}
    assert catalog[0x1234] == [{
        "namespace": "Game.Ability",
        "class": "Executor",
        "method": "Run",
        "line": 2,
        "source": str(source.resolve()),
    }]


def test_catalog_accepts_private_load_key_value_inventory(tmp_path: Path) -> None:
    source = tmp_path / "private-methods.txt"
    source.write_text(
        "CLASS|label=root|name=Transform|namespace=UnityEngine|token=0x2000179\n"
        "METHOD|label=root|index=97|name=get_position_Injected|rva=0x1ea22170\n",
        encoding="utf-8",
    )
    assert _catalog(source)[0x1EA22170][0]["class"] == "Transform"
    assert _catalog(source)[0x1EA22170][0]["method"] == "get_position_Injected"


def test_stratum_never_promotes_frequency_to_semantic_identity() -> None:
    assert _stratum(188, [], []) == "UBIQUITOUS_ACROSS_SELECTED_TYPES"
    assert _stratum(4, [], []) == "SHARED_UNIDENTIFIED"
    assert _stratum(1, [], []) == "NARROW_UNIDENTIFIED"
    assert _stratum(1, [{"method": "Run"}], []) == "SOURCE_IDENTIFIED_OR_ANNOTATED"
    assert _stratum(1, [], [{"kind": "source_note"}]) == "SOURCE_IDENTIFIED_OR_ANNOTATED"


def test_metadata_annotation_requires_declared_init_rva(tmp_path: Path) -> None:
    source = tmp_path / "metadata.txt"
    source.write_text("metadata init-rva=0x279250 status=observed\n", encoding="utf-8")
    result = _metadata_annotation(source)
    assert result is not None
    rva, annotation = result
    assert rva == 0x279250
    assert annotation["kind"] == "source_declared_metadata_init_rva"
    assert annotation["line"] == 1
    assert annotation["source"] == str(source.resolve())

    missing = tmp_path / "missing.txt"
    missing.write_text("metadata status=observed\n", encoding="utf-8")
    assert _metadata_annotation(missing) is None
