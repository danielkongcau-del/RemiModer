from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller_callsite_join import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_exact_runtime_caller_rva_is_source_identified(tmp_path: Path) -> None:
    analysis = {"runtime_callsites": [{"point": "Target/entry", "callsite_rva": 0x1010,
        "call_kind": "indirect", "event_count": 3,
        "caller_runtime_function": {"begin_rva": 0x1000, "end_rva": 0x1020}}]}
    catalog = "\n".join(["CLASS|1|x|x|Owner", "METHOD|1|7|Method|0x1000|slot|return=Void|params=0"])
    catalog_path = tmp_path / "catalog.txt"
    catalog_path.write_text(catalog, encoding="utf-8")
    result = run(_write(tmp_path / "analysis.json", analysis), [catalog_path], tmp_path / "out")
    assert result["summary"]["source_identified_rows"] == 1
    assert result["runtime_callsite_rows"][0]["caller_method_identities"][0]["owner"] == "Owner"


def test_unknown_runtime_caller_remains_unresolved(tmp_path: Path) -> None:
    analysis = {"runtime_callsites": [{"point": "Target/entry", "callsite_rva": 0x2010,
        "call_kind": "direct", "event_count": 1,
        "caller_runtime_function": {"begin_rva": 0x2000, "end_rva": 0x2020}}]}
    catalog_path = tmp_path / "catalog.txt"
    catalog_path.write_text("CLASS|1|x|x|Owner\n", encoding="utf-8")
    result = run(_write(tmp_path / "analysis.json", analysis), [catalog_path], tmp_path / "out")
    assert result["runtime_callsite_rows"][0]["identity_status"] == "UNRESOLVED"


def test_entry_acceptance_v2_runtime_evidence_is_normalized(tmp_path: Path) -> None:
    analysis = {"schema": "uc.entry-evidence-acceptance.v2", "points": [{
        "point": "Target/entry",
        "runtime_caller_evidence": [{
            "callsite_rva": 0x3010,
            "call_kind": "indirect",
            "observation_count": 9,
            "caller_runtime_function": {"begin_rva": 0x3000, "end_rva": 0x3020},
        }],
    }]}
    catalog_path = tmp_path / "catalog.txt"
    catalog_path.write_text(
        "CLASS|3|x|x|OwnerV2\nMETHOD|3|4|MethodV2|0x3000|slot|return=Void|params=0",
        encoding="utf-8",
    )
    result = run(_write(tmp_path / "analysis.json", analysis), [catalog_path], tmp_path / "out")
    assert result["summary"]["source_identified_rows"] == 1
    assert result["runtime_callsite_rows"][0]["observation_count"] == 9
    assert result["runtime_callsite_rows"][0]["caller_method_identities"][0]["method"] == "MethodV2"
