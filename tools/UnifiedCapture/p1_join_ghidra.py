"""Join Ghidra instruction/flow exports to P1 mechanical candidates."""
from __future__ import annotations

import argparse
import base64
import copy
import csv
import json
from pathlib import Path

from uc.native_manifest import sha256_file, validate_exit_manifest


def read_export(path: Path):
    headers = {}
    table_lines = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for line in stream:
            if line.startswith("#"):
                key, value = line.rstrip("\r\n").split("\t", 1)
                headers[key[1:]] = value
            else:
                table_lines.append(line)
    reader = csv.DictReader(table_lines, delimiter="\t")
    groups = {}
    for row in reader:
        function_id = base64.b64decode(row["function_id_base64"]).decode("utf-8")
        key = (row["module"], function_id, int(row["entry_rva"]), int(row["runtime_begin_rva"]),
               int(row["runtime_end_rva"]), row["role_candidate"])
        parsed = {
            "rva": int(row["instruction_rva"]),
            "bytes": row["bytes"].lower(),
            "mnemonic": row["mnemonic"].lower(),
            "flow_type": row["flow_type"],
            "flows": [int(value) for value in row["flow_rvas"].split(",") if value],
            "fallthrough": int(row["fallthrough_rva"]) if row["fallthrough_rva"] else None,
            "incoming_references": [int(value) for value in row["incoming_reference_rvas"].split(",") if value],
        }
        groups.setdefault(key, {})[parsed["rva"]] = parsed
    return headers, groups


def ghidra_reachable(rows: dict[int, dict], entry: int, begin: int, end: int):
    reachable = set()
    queue = [entry]
    while queue:
        cursor = queue.pop()
        while cursor in rows and cursor not in reachable:
            ins = rows[cursor]
            reachable.add(cursor)
            flow = ins["flow_type"].upper()
            if ins["mnemonic"].startswith("ret") or "TERMINATOR" in flow:
                break
            if "JUMP" in flow:
                for target in ins["flows"]:
                    if begin <= target < end and target not in reachable:
                        queue.append(target)
                if "CONDITIONAL" not in flow:
                    break
            if ins["fallthrough"] is None:
                break
            cursor = ins["fallthrough"]
    return reachable


def canonical_mnemonic(value: str) -> str:
    value = value.lower()
    aliases = {
        "jz": "je", "jnz": "jne", "jnc": "jae", "jc": "jb",
        "setz": "sete", "setnz": "setne", "cmovz": "cmove",
        "cmovnz": "cmovne", "cmovnc": "cmovae", "movabs": "mov",
        "dec.lock": "lock dec",
    }
    return aliases.get(value, value)


def compare_range(function: dict, runtime: dict, cfg: dict, instructions: list[dict], groups: dict):
    role = runtime["runtime_function_role"]
    key = (function["module"], function["function_id"], function["entry_rva"],
           runtime["begin_rva"], runtime["end_rva"], role)
    rows = groups.get(key)
    if rows is None:
        return {"runtime_function_begin_rva": runtime["begin_rva"], "runtime_function_role": role,
                "ghidra_export_present": False, "instruction_agreement": False,
                "reasons": ["runtime-range-missing-from-ghidra-export"]}
    reachable = set(cfg["reachable_instruction_rvas"])
    capstone_rows = {ins["rva"]: ins for ins in instructions}
    ghidra_set = ghidra_reachable(rows, runtime["begin_rva"], runtime["begin_rva"], runtime["end_rva"])
    cap_rets = sorted(ins["rva"] for ins in instructions
                      if ins["rva"] in reachable and ins["mnemonic"].startswith("ret"))
    ghidra_rets = sorted(rva for rva in ghidra_set if rows[rva]["mnemonic"].startswith("ret"))
    missing = sorted(reachable - set(rows))
    extra = sorted(ghidra_set - reachable)
    byte_mismatch = sorted(rva for rva in reachable & set(rows)
                           if capstone_rows[rva]["bytes"] != rows[rva]["bytes"])
    mnemonic_mismatch = sorted(rva for rva in reachable & set(rows)
                               if canonical_mnemonic(capstone_rows[rva]["mnemonic"]) !=
                               canonical_mnemonic(rows[rva]["mnemonic"]))
    reasons = []
    if missing: reasons.append("capstone-reachable-instruction-missing-in-ghidra")
    if extra: reasons.append("ghidra-reachable-instruction-missing-in-capstone-cfg")
    if byte_mismatch: reasons.append("instruction-bytes-disagree")
    if mnemonic_mismatch: reasons.append("instruction-mnemonics-disagree")
    if cap_rets != ghidra_rets: reasons.append("reachable-ret-set-disagrees")
    return {
        "runtime_function_begin_rva": runtime["begin_rva"],
        "runtime_function_role": role,
        "ghidra_export_present": True,
        "instruction_agreement": not reasons,
        "capstone_reachable_count": len(reachable),
        "ghidra_reachable_count": len(ghidra_set),
        "missing_instruction_rvas": missing,
        "extra_reachable_instruction_rvas": extra,
        "byte_mismatch_rvas": byte_mismatch,
        "mnemonic_mismatch_rvas": mnemonic_mismatch,
        "capstone_reachable_ret_rvas": cap_rets,
        "ghidra_reachable_ret_rvas": ghidra_rets,
        "incoming_reference_scope_complete": False,
        "reasons": reasons,
    }


def run(candidate: Path, exports: list[Path], output: Path):
    if output.exists():
        raise FileExistsError(f"joined output is immutable: {output}")
    value = json.loads(candidate.read_text(encoding="utf-8-sig"))
    all_groups = {}
    export_sources = []
    expected_hashes = {source.get("alias"): source["sha256"] for source in value["sources"] if source["kind"] == "module"}
    for path in exports:
        headers, groups = read_export(path)
        program = headers.get("program", "").lower()
        module = "unity" if program == "unityplayer.dll" else "game" if program == "gameassembly.dll" else None
        if module is None or headers.get("executable_sha256", "").lower() != expected_hashes[module]:
            raise ValueError(f"Ghidra export program identity mismatch: {path}")
        overlap = set(all_groups) & set(groups)
        if overlap:
            raise ValueError(f"duplicate Ghidra target groups: {len(overlap)}")
        all_groups.update(groups)
        export_sources.append({"kind": "ghidra-export", "module": module, "path": str(path.resolve()),
                               "sha256": sha256_file(path), "program_sha256": headers["executable_sha256"],
                               "scope": "targeted-ranges; incoming references not globally complete" if module == "game"
                                        else "existing fully analyzed project; still not proof of indirect references"})
    joined = copy.deepcopy(value)
    agreements = 0
    missing_exports = 0
    for source_function, function in zip(value["functions"], joined["functions"]):
        primary_runtime = next(runtime for runtime in source_function["runtime_functions"]
                               if runtime["runtime_function_role"] == "primary")
        range_inputs = [(primary_runtime, source_function["capstone_cfg"], source_function["capstone_instructions"])]
        range_inputs.extend((item["runtime"], item["capstone_cfg"], item["capstone_instructions"])
                            for item in source_function.get("capstone_fragment_analyses", []))
        range_verifications = [compare_range(source_function, runtime, cfg, instructions, all_groups)
                               for runtime, cfg, instructions in range_inputs]
        verification = {
            "ghidra_export_present": all(item["ghidra_export_present"] for item in range_verifications),
            "instruction_agreement": all(item["instruction_agreement"] for item in range_verifications),
            "runtime_ranges": range_verifications,
            "incoming_reference_scope_complete": False,
            "reasons": sorted({reason for item in range_verifications for reason in item["reasons"]}),
        }
        function["ghidra_verification"] = verification
        if verification["instruction_agreement"]:
            agreements += 1
            function["promotion_blockers"] = [item for item in function["promotion_blockers"]
                                               if item != "ghidra-cfg-not-yet-joined"]
            function["promotion_blockers"].append("ghidra-incoming-reference-scope-not-complete")
        else:
            missing_exports += not verification["ghidra_export_present"]
    joined["sources"].extend(export_sources)
    joined["summary"]["functions_with_ghidra_capstone_reachable_cfg_agreement"] = agreements
    joined["summary"]["functions_missing_ghidra_primary_export"] = missing_exports
    joined["summary"]["activation_ready_functions"] = 0
    validate_exit_manifest(joined)
    output.mkdir(parents=True)
    out_manifest = output / "native-exit-manifest.ghidra-joined.json"
    out_manifest.write_text(json.dumps(joined, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = [
        "# P1 Ghidra/Capstone join",
        "",
        f"- 首批函数：{len(joined['functions'])}。",
        f"- 可达 CFG/ret 集合一致：{agreements}/{len(joined['functions'])}。",
        f"- 缺少 Ghidra primary 导出：{missing_exports}。",
        "- 全部函数仍保持 activation_ready=false：入边完整性、runtime-function 角色、Gum dry-run 和 relocation 异常测试尚未闭合。",
        "",
        "此 join 只消除一个晋升阻塞项，不把定点 Ghidra 分析冒充全模块调用图。",
    ]
    (output / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    index = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            index.append({"file": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)})
    (output / "evidence-index.json").write_text(json.dumps({
        "schema": "uc.p1-ghidra-join-index.v1", "sources": [str(candidate.resolve()), *map(lambda p: str(p.resolve()), exports)],
        "files": index, "sealed": True, "activation_ready": False,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "agreements": agreements,
                      "functions": len(joined["functions"]), "activation_ready": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--ghidra-export", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.candidate.resolve(), [path.resolve() for path in args.ghidra_export], args.out.resolve())
