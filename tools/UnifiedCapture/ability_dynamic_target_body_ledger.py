"""Record mechanical native-body evidence for uncatalogued dynamic targets."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path.resolve()), "size": path.stat().st_size,
            "sha256": file_hash(path)}


def _fast_path_field_load(instructions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Recognize only the exact conditional fast-path load/return instruction shape."""
    for index in range(len(instructions) - 4):
        row = instructions[index]
        match = re.fullmatch(r"rax, qword ptr \[rsi \+ (0x[0-9a-f]+)\]", row["operands"])
        if (row["mnemonic"] == "mov" and match
                and instructions[index + 1]["mnemonic"] == "add"
                and instructions[index + 1]["operands"] == "rsp, 0x20"
                and instructions[index + 2]["mnemonic"] == "pop"
                and instructions[index + 2]["operands"] == "rsi"
                and instructions[index + 3]["mnemonic"] == "ret"):
            return {"load_rva": int(row["rva"]), "base_register": "rsi",
                    "field_offset": int(match.group(1), 0), "return_register": "rax"}
    return None


def _immediate_call_pairs(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for left, right in zip(instructions, instructions[1:]):
        match = re.fullmatch(r"ecx, (0x[0-9a-f]+)", left["operands"])
        if (left["mnemonic"] == "mov" and match and right["mnemonic"] == "call"
                and right.get("direct_target_rva") is not None):
            rows.append({"immediate_load_rva": int(left["rva"]),
                         "ecx_immediate": int(match.group(1), 0),
                         "call_rva": int(right["rva"]),
                         "call_target_rva": int(right["direct_target_rva"])})
    return rows


def build(method_join_path: Path, multipass_scan_path: Path,
          game_path: Path, out: Path) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    method_join = _load(method_join_path)
    scan = _load(multipass_scan_path)
    if method_join.get("schema") != "uc.ability-dynamic-dispatch-authoritative-method-join.v1":
        raise ValueError("unsupported authoritative method join")
    if scan.get("schema") != "uc.ability-private-load-multipass-scan.v1":
        raise ValueError("unsupported multipass scan")
    if not scan.get("summary", {}).get("scan_complete"):
        raise ValueError("multipass owner scan is not complete")

    unresolved = {int(row["target_rva"]) for row in method_join["targets"]
                  if row.get("catalog_status") == "NO_CATALOG_MATCH"}
    scan_targets = {int(re.search(r"slot=(0x[0-9a-fA-F]+)", row).group(1), 0)
                    for row in scan["targets"]}
    if unresolved != scan_targets:
        raise ValueError("owner-scan targets differ from uncatalogued dynamic targets")
    if scan["summary"].get("exact_positive_matches") != 0:
        raise ValueError("body ledger requires unresolved zero-match owner scan")

    image = NativePE(game_path)
    rows = []
    for target_rva in sorted(unresolved):
        function = image.by_start.get(target_rva)
        if function is None:
            raise ValueError(f"target is not an exact PDATA entry: {target_rva:#x}")
        decoded = image.decode(function)
        if not decoded["all_declared_bytes_decoded"]:
            raise ValueError(f"target PDATA body did not decode completely: {target_rva:#x}")
        raw = image.bytes_at(function.begin, function.end - function.begin)
        instructions = [{
            "rva": int(row["rva"]), "bytes": row["bytes"],
            "mnemonic": row["mnemonic"], "operands": row["operands"],
            "groups": row.get("groups", []),
            "direct_target_rva": row.get("direct_target_rva"),
        } for row in decoded["instructions"]]
        cfg = image.cfg(function)
        rows.append({
            "target_rva": target_rva,
            "pdata_begin_rva": function.begin,
            "pdata_end_rva": function.end,
            "raw_size": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "instruction_count": len(instructions),
            "linear_decode_complete": True,
            "reachable_instruction_count": len(cfg["reachable_instruction_rvas"]),
            "cfg_terminals": cfg["terminals"],
            "fast_path_field_load": _fast_path_field_load(instructions),
            "ecx_immediate_direct_call_pairs": _immediate_call_pairs(instructions),
            "instructions": instructions,
        })

    summary = {
        "uncatalogued_dynamic_targets": len(unresolved),
        "exact_pdata_bodies": len(rows),
        "fully_decoded_bodies": sum(row["linear_decode_complete"] for row in rows),
        "complete_private_load_owner_scan_types": scan["summary"]["covered_types"],
        "private_load_exact_owner_matches": scan["summary"]["exact_positive_matches"],
        "exact_fast_path_field_loads": sum(row["fast_path_field_load"] is not None for row in rows),
    }
    artifact = {
        "schema": "uc.ability-dynamic-target-body-ledger.v1",
        "sources": {"authoritative_method_join": _source(method_join_path),
                    "multipass_owner_scan": _source(multipass_scan_path),
                    "game_module": _source(game_path)},
        "summary": summary,
        "bounded_conclusions": [
            "each target is a runtime-observed GameAssembly RVA and an exact completely decoded PDATA entry",
            "instruction rows and fast-path field loads are mechanical decodes, not semantic names",
            "ECX immediate and direct-call pairs are preserved without assigning hotfix or dispatch semantics",
            "the complete private-load scan found no exact MethodInfo code-RVA owner in its 9121-type scope",
            "absence from the harvested MethodInfo scope does not prove the code is unrelated to managed execution",
        ],
        "runtime_needed_now": False,
        "targets": rows,
    }
    out.mkdir(parents=True)
    artifact_path = out / "ability-dynamic-target-body-ledger.json"
    artifact_path.write_bytes(canonical(artifact))
    report = {"schema": "uc.ability-dynamic-target-body-ledger-report.v1",
              "artifact": {"path": str(artifact_path), "sha256": file_hash(artifact_path)},
              "summary": summary, "runtime_needed_now": False}
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method-join", type=Path, required=True)
    parser.add_argument("--multipass-scan", type=Path, required=True)
    parser.add_argument("--game", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        return build(args.method_join.resolve(), args.multipass_scan.resolve(),
                     args.game.resolve(), args.out.resolve())
    except Exception as error:
        write_failure(args.out, "ability_dynamic_target_body_ledger", error,
                      {"method_join": str(args.method_join),
                       "multipass_scan": str(args.multipass_scan), "game": str(args.game)})
        raise


if __name__ == "__main__":
    run_main(main)
