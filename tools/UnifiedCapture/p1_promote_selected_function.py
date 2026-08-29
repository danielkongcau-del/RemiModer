"""Promote terminal/completeness claims for one function from closed evidence.

Only normal RET and architecturally trapping INT3 terminals are recognized.
This pass does not promote incoming-edge completeness or backend contracts.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest


def run(manifest_path: Path, function_id: str, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    value = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(value)
    functions = [row for row in value["functions"] if row["function_id"] == function_id]
    if len(functions) != 1:
        raise ValueError("function id is not unique")
    function = functions[0]
    sources = {row["alias"]: row for row in value["sources"] if row.get("kind") == "module"}
    module_source = sources[function["module"]]
    image = NativePE(Path(module_source["path"]))
    if file_hash(image.path) != function["module_sha256"]:
        raise ValueError("module identity changed")
    runtime = function["runtime_functions"]
    if len(runtime) != 1 or runtime[0]["runtime_function_role"] != "primary" or not runtime[0]["role_verified"]:
        raise ValueError("single verified primary runtime range required")
    unwind = runtime[0]["unwind"]
    if unwind["has_exception_handler"] or unwind["has_unwind_handler"] or unwind["has_chain_info"]:
        raise ValueError("handler/chain runtime ranges require separate semantic analysis")
    verification = function["ghidra_verification"]
    if not verification["instruction_agreement"] or len(verification["runtime_ranges"]) != 1:
        raise ValueError("Ghidra/Capstone agreement required")
    range_check = verification["runtime_ranges"][0]
    if range_check["capstone_reachable_ret_rvas"] != range_check["ghidra_reachable_ret_rvas"]:
        raise ValueError("reachable RET sets differ")
    cfg_terminals = {row["rva"]: row for row in function["capstone_cfg"]["terminals"]}
    normal_rvas = {row["ret_rva"] for row in function["normal_exits"]}
    if normal_rvas != set(range_check["capstone_reachable_ret_rvas"]):
        raise ValueError("normal-exit candidates do not equal jointly reachable RET set")
    trap_evidence = []
    for rva, terminal in cfg_terminals.items():
        instruction = next((row for row in function["capstone_instructions"] if row["rva"] == rva), None)
        if rva in normal_rvas:
            if instruction is None or instruction["mnemonic"] != "ret":
                raise ValueError("normal terminal is not RET")
            continue
        if instruction is None or instruction["mnemonic"] != "int3" or instruction["bytes"] != "cc":
            raise ValueError("non-return terminal is not an architectural INT3 trap")
        terminal["terminal_semantics"] = "terminal_trap"
        terminal["terminal_semantics_verified"] = True
        terminal["evidence"] = ["capstone-reachable-byte-cc", "ghidra-capstone-instruction-agreement"]
        trap_evidence.append({"rva": rva, "bytes": "cc", "instruction": "int3"})
    for exit_site in function["normal_exits"]:
        exit_site["terminal_semantics_verified"] = True
        exit_site["terminal_evidence"] = ["joint-ghidra-capstone-reachable-ret-set",
                                          "single-verified-primary-runtime-range"]
    for terminal_site in function["terminal_sites"]:
        if terminal_site["rva"] not in cfg_terminals or cfg_terminals[terminal_site["rva"]]["terminal_semantics"] != "terminal_trap":
            raise ValueError("terminal-site ledger differs from CFG terminal set")
        terminal_site["terminal_semantics"] = "terminal_trap"
        terminal_site["terminal_semantics_verified"] = True
        terminal_site["evidence"] = ["capstone-reachable-byte-cc", "ghidra-capstone-instruction-agreement"]
    if function.get("cold_fragment_transfers") or len(runtime) != 1:
        raise ValueError("cold fragment set is not empty")
    if any(row["terminal_semantics"] in ("tail_transfer", "terminal_branch", "unresolved")
           for row in cfg_terminals.values()):
        raise ValueError("tail/unresolved terminal remains")
    function["completeness"] = {"normal_exit_set_complete": True, "tail_set_complete": True,
                                "cold_fragments_complete": True}
    function["terminal_completeness_evidence"] = {
        "runtime_range_count": 1, "normal_ret_rvas": sorted(normal_rvas),
        "trap_terminals": trap_evidence, "tail_transfers": [], "cold_fragments": [],
        "scope": "joint reachable CFG inside exact primary .pdata range"}
    blockers = [row for row in function.get("promotion_blockers", [])
                if row not in ("ghidra-incoming-reference-scope-not-complete",)]
    # Incoming-reference scope remains a candidate-window blocker, not a
    # terminal-set blocker; preserve it explicitly under its accurate name.
    if "incoming-edge-set-not-yet-proven-complete" not in blockers:
        blockers.append("incoming-edge-set-not-yet-proven-complete")
    function["promotion_blockers"] = blockers
    value["status"] = "partially-verified"
    verified = set(value.get("terminal_verified_functions", []));verified.add(function_id)
    value["terminal_verified_functions"] = sorted(verified)
    value["summary"]["terminal_complete_functions"] = sum(
        row["completeness"]["normal_exit_set_complete"] and row["completeness"]["tail_set_complete"] and
        row["completeness"]["cold_fragments_complete"] for row in value["functions"])
    value["summary"]["activation_ready_functions"] = 0
    output.mkdir(parents=True)
    destination = output / "native-exit-manifest.selected-terminal-promoted.json"
    destination.write_bytes(canonical(value))
    report = {"schema": "uc.selected-terminal-promotion.v1", "function_id": function_id,
              "terminal_semantics_complete": True, "normal_exit_set_complete": True,
              "tail_set_complete": True, "cold_fragments_complete": True,
              "incoming_edges_complete": False, "backend_patch_contract_ready": False,
              "activation_ready": False, "manifest": {"path": str(destination),
                                                        "sha256": file_hash(destination)},
              "source": {"path": str(manifest_path), "sha256": file_hash(manifest_path)}}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "manifest": str(destination),
                      "sha256": file_hash(destination), "function_id": function_id,
                      "terminal_complete": True, "activation_ready": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--function-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.function_id, args.out.resolve())
