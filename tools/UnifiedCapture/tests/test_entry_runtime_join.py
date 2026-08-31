from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from entry_runtime_join import run
from uc.model import canonical


def _write(path: Path, value: object) -> Path:
    path.write_bytes(canonical(value))
    return path


def test_chained_pdata_fragment_is_joined_to_logical_root(tmp_path: Path) -> None:
    acceptance = {
        "accepted": True, "generation": 3, "session": "fixture",
        "points": [{"point": "UnityPlayer.0x2000/entry", "function_id": "UnityPlayer.0x2000",
                    "evidence_scope": "marked_window", "runtime_caller_evidence": [{
                        "caller_runtime_function": {"begin_rva": 0x1100, "end_rva": 0x1180},
                        "callsite_rva": 0x1120, "call_kind": "direct", "observation_count": 7,
                        "first_qpc": 10, "last_qpc": 20}]}]}
    manifest = {"functions": [{"function_id": "UnityPlayer.0x1000", "entry_rva": 0x1000},
                               {"function_id": "UnityPlayer.0x2000", "entry_rva": 0x2000}]}
    frontier = {"functions": {"0x1000": {"rootRva": 0x1000, "fragments": [
        {"rva": 0x1000, "declaredEnd": 0x1080}, {"rva": 0x1100, "declaredEnd": 0x1180}]}},
        "directEdges": [{"rva": 0x1120, "logicalRoot": "0x1000", "targetRva": "0x2000",
                         "bytes": "e8"}], "indirectSites": []}
    output = tmp_path / "out"
    result = run(_write(tmp_path / "acceptance.json", acceptance),
                 _write(tmp_path / "manifest.json", manifest),
                 _write(tmp_path / "frontier.json", frontier), output)
    assert result["checks"]["all_logical_edges_static_verified"] is True
    assert result["logical_runtime_edges"] == [{
        "caller_point": "UnityPlayer.0x1000/entry", "callee_point": "UnityPlayer.0x2000/entry",
        "callsite_rvas": [0x1120], "observation_count": 7, "first_qpc": 10, "last_qpc": 20,
        "call_kinds": ["direct"], "evidence_scope": "marked_window",
        "evidence": "runtime return address + unique predecessor call + PDATA owner + audited logical-fragment membership"}]


def test_logical_owner_requires_matching_audited_callsite(tmp_path: Path) -> None:
    acceptance = {"accepted": True, "points": [{"point": "UnityPlayer.0x2000/entry",
        "function_id": "UnityPlayer.0x2000", "runtime_caller_evidence": [{
            "caller_runtime_function": {"begin_rva": 0x1000, "end_rva": 0x1080},
            "callsite_rva": 0x1020, "call_kind": "direct", "observation_count": 1,
            "first_qpc": 1, "last_qpc": 1}]}]}
    manifest = {"functions": [{"function_id": "UnityPlayer.0x1000", "entry_rva": 0x1000},
                               {"function_id": "UnityPlayer.0x2000", "entry_rva": 0x2000}]}
    frontier = {"functions": {"0x1000": {"rootRva": 0x1000,
        "fragments": [{"rva": 0x1000, "declaredEnd": 0x1080}]}},
        "directEdges": [], "indirectSites": []}
    result = run(_write(tmp_path / "a.json", acceptance), _write(tmp_path / "m.json", manifest),
                 _write(tmp_path / "f.json", frontier), tmp_path / "out")
    assert result["logical_runtime_edges"] == []
    assert result["checks"]["invalid_static_join_count"] == 1


def test_retained_caller_without_pdata_owner_is_preserved_as_unresolved(tmp_path: Path) -> None:
    acceptance = {"accepted": True, "points": [{"point": "Game.0x2000/entry",
        "function_id": "Game.0x2000", "runtime_caller_evidence": [{
            "callsite_status": "UNRESOLVED", "return_address": 0x123456,
            "observation_count": 9, "first_qpc": 1, "last_qpc": 2}]}]}
    manifest = {"functions": [{"function_id": "Game.0x2000", "entry_rva": 0x2000}]}
    frontier = {"functions": {}, "directEdges": [], "indirectSites": []}
    result = run(_write(tmp_path / "a.json", acceptance), _write(tmp_path / "m.json", manifest),
                 _write(tmp_path / "f.json", frontier), tmp_path / "out")
    assert result["logical_runtime_edges"] == []
    assert result["checks"]["unresolved_caller_evidence_count"] == 1
    assert result["unresolved_caller_evidence"][0]["evidence"]["return_address"] == 0x123456
