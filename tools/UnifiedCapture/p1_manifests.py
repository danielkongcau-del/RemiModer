"""Generate P1 mechanical exit/callsite evidence from fixed local game images.

The output is deliberately not activation-ready. Ghidra CFG agreement and the
pinned Gum relocator dry-run are later promotion gates.
"""
from __future__ import annotations

import argparse
import json
import base64
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from uc.native_manifest import (
    CALLSITE_SCHEMA,
    EXIT_SCHEMA,
    NativePE,
    exit_probe_candidates,
    looks_like_x64_tail_transfer,
    sha256_file,
    validate_callsite_manifest,
    validate_exit_manifest,
)

HERE = Path(__file__).resolve().parent
GUM_LIB = HERE / "vendor/gum-17.17.0/frida-gum.lib"
GENERATOR_VERSION = "p1-manifests-1"


def write_json(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def source_path(plan: dict, image: str, expected_hash: str) -> Path:
    matches = []
    for source in plan["sources"].values():
        candidate = Path(source["path"])
        if candidate.name.lower() == image.lower() and source["sha256"] == expected_hash:
            matches.append(candidate)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one source for {image}/{expected_hash}, found {len(matches)}")
    path = matches[0].resolve()
    if sha256_file(path) != expected_hash:
        raise ValueError(f"module source changed: {path}")
    return path


def runtime_function_record(pe: NativePE, row, role: str) -> dict:
    unwind = pe.unwind(row)
    return {
        "begin_rva": row.begin,
        "end_rva": row.end,
        "unwind_rva": row.unwind_rva,
        "runtime_function_role": role,
        "role_verified": role in ("primary", "cold_fragment"),
        "role_evidence": "capture-plan-exact-pdata-entry" if role == "primary" else "PE-UNW_FLAG_CHAININFO-to-primary",
        "unwind": unwind,
    }


def chained_to_primary(pe: NativePE, row, primary) -> bool:
    if row == primary:
        return True
    chained = pe.unwind(row)["chained_runtime_function"]
    return bool(chained and chained["begin_rva"] == primary.begin and chained["end_rva"] == primary.end
                and chained["unwind_rva"] == primary.unwind_rva)


def logical_function_analysis(pe: NativePE, primary):
    queue = [primary]
    queued = {primary.begin}
    ranges = []
    exits = []
    unresolved = []
    transfers = []
    while queue:
        row = queue.pop(0)
        role = "primary" if row == primary else "cold_fragment"
        cfg = pe.cfg(row)
        decoded = pe.decode(row)["instructions"]
        reachable = set(cfg["reachable_instruction_rvas"])
        ranges.append({
            "runtime": runtime_function_record(pe, row, role),
            "capstone_cfg": cfg,
            "capstone_instructions": [ins for ins in decoded if ins["rva"] in reachable],
        })
        exits.extend(exit_probe_candidates(pe, row, cfg))
        for terminal in cfg["terminals"]:
            if terminal["terminal_semantics"] == "normal_return":
                continue
            enriched = dict(terminal, source_runtime_function_begin_rva=row.begin)
            target = terminal.get("target_rva")
            destination = pe.containing(target) if target is not None else None
            if destination is not None and chained_to_primary(pe, destination, primary):
                enriched["resolved_as"] = "cold_fragment_transfer"
                enriched["destination_runtime_function_begin_rva"] = destination.begin
                transfers.append(enriched)
                if destination.begin not in queued:
                    queue.append(destination)
                    queued.add(destination.begin)
            else:
                if (enriched.get("reason") == "indirect-branch" and
                        looks_like_x64_tail_transfer(pe, row, enriched["rva"])):
                    enriched["terminal_semantics"] = "tail_transfer"
                    enriched["mechanical_only"] = False
                    enriched["terminal_semantics_verified_by"] = [
                        "terminal-indirect-jump-at-runtime-function-end",
                        "x64-stack-epilogue-pattern",
                        "PE-unwind-linked-runtime-range",
                    ]
                unresolved.append(enriched)
    ranges.sort(key=lambda item: item["runtime"]["begin_rva"])
    exits.sort(key=lambda item: item["ret_rva"])
    return ranges, exits, unresolved, transfers


def build_exit_manifest(plan: dict, images: dict[str, NativePE], sources: list[dict]) -> tuple[dict, list[dict]]:
    functions = []
    ghidra_targets = []
    gum_hash = sha256_file(GUM_LIB)
    points = [point for point in plan["points"] if point["backend"] == "gum_probe"]
    for point in points:
        pe = images[point["module"]]
        row = pe.by_start.get(point["rva"])
        if row is None:
            raise ValueError(f"not an exact .pdata entry: {point['id']} {point['rva']:#x}")
        ranges, exits, terminal_sites, fragment_transfers = logical_function_analysis(pe, row)
        primary_analysis = next(item for item in ranges if item["runtime"]["begin_rva"] == row.begin)
        cross = [terminal for terminal in terminal_sites if "target_rva" in terminal]
        indirect = [terminal for terminal in terminal_sites
                    if terminal.get("reason") == "indirect-branch" and terminal["terminal_semantics"] == "unresolved"]
        blockers = ["ghidra-cfg-not-yet-joined", "gum-backend-dry-run-not-yet-run",
                    "incoming-edge-set-not-yet-proven-complete", "relocated-span-fault-test-not-yet-run"]
        if cross:
            blockers.append("cross-runtime-function-terminal-needs-role-classification")
        if indirect:
            blockers.append("indirect-terminal-unresolved")
        functions.append({
            "function_id": point["id"],
            "module": point["module"],
            "module_sha256": plan["modules"][point["module"]]["sha256"],
            "entry_rva": point["rva"],
            "entry_expected_prefix": point["expected_prefix"],
            "entry_evidence": point["evidence"],
            "exit_capture_requirement": "none",
            "runtime_functions": [item["runtime"] for item in ranges],
            "capstone_cfg": primary_analysis["capstone_cfg"],
            "capstone_instructions": primary_analysis["capstone_instructions"],
            "capstone_fragment_analyses": [item for item in ranges if item is not primary_analysis],
            "normal_exits": exits,
            "terminal_sites": terminal_sites,
            "cold_fragment_transfers": fragment_transfers,
            "promotion_blockers": blockers,
            "completeness": {
                "normal_exit_set_complete": False,
                "tail_set_complete": False,
                "cold_fragments_complete": False,
            },
        })
        for item in ranges:
            runtime = item["runtime"]
            seeds = {runtime["begin_rva"]}
            for resolved in item["capstone_cfg"]["resolved_indirect_branches"]:
                seeds.update(resolved["target_rvas"])
            ghidra_targets.append({
                "module": point["module"], "function_id": point["id"], "entry_rva": point["rva"],
                "runtime_function_begin_rva": runtime["begin_rva"], "runtime_function_end_rva": runtime["end_rva"],
                "role_candidate": runtime["runtime_function_role"],
                "seed_rvas": sorted(seeds),
            })
    exit_count = sum(len(function["normal_exits"]) for function in functions)
    with_ret = sum(bool(function["normal_exits"]) for function in functions)
    span5 = sum(any(candidate["candidate_for_minimum_span"] == 5
                    for site in function["normal_exits"] for candidate in site["probe_candidates"])
                for function in functions)
    manifest = {
        "schema": EXIT_SCHEMA,
        "status": "mechanical-candidate",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "generator": {"name": GENERATOR_VERSION, "path": str(Path(__file__).resolve()),
                      "sha256": sha256_file(Path(__file__).resolve())},
        "sources": sources,
        "backend_capability": {
            "backend": "gum_instruction_probe",
            "backend_build": "frida-gum-17.17.0-windows-x86_64",
            "backend_build_hash": gum_hash,
            "redirect_span_is_schema_constant": False,
            "dry_run_status": "NOT_RUN",
            "relocated_span_fault_test": "NOT_RUN",
            "cet_cfg_test": "NOT_RUN",
        },
        "functions": functions,
        "summary": {
            "target_functions": len(functions),
            "exact_pdata_entries": len(functions),
            "functions_with_reachable_ret_candidates": with_ret,
            "reachable_ret_candidates": exit_count,
            "linked_cold_fragments": sum(len(function["runtime_functions"]) - 1 for function in functions),
            "functions_with_minimum_5_byte_pure_epilogue_candidate": span5,
            "activation_ready_functions": 0,
            "static_result_is_controller_complete": False,
        },
    }
    validate_exit_manifest(manifest)
    return manifest, ghidra_targets


def build_callsite_manifest(plan: dict, images: dict[str, NativePE], sources: list[dict]) -> dict:
    points = [point for point in plan["points"] if point["backend"] == "gum_probe"]
    points_by_module = defaultdict(list)
    for point in points:
        points_by_module[point["module"]].append(point)
    targets = []
    totals = Counter()
    for module, module_points in sorted(points_by_module.items()):
        pe = images[module]
        xrefs = pe.direct_xrefs({point["rva"] for point in module_points})
        by_target = defaultdict(list)
        for xref in xrefs:
            by_target[xref["target_rva"]].append(xref)
            totals[xref["kind"]] += 1
        for point in module_points:
            direct = by_target[point["rva"]]
            targets.append({
                "function_id": point["id"],
                "module": module,
                "entry_rva": point["rva"],
                "direct_static_sites": direct,
                "direct_static_site_count": len(direct),
                "static_direct_enumeration_is_complete": False,
                "runtime_observed_callsite_required_for_indirect_dispatch": True,
            })
    covered = sum(bool(target["direct_static_sites"]) for target in targets)
    manifest = {
        "schema": CALLSITE_SCHEMA,
        "status": "mechanical-candidate",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "generator": {"name": GENERATOR_VERSION, "path": str(Path(__file__).resolve()),
                      "sha256": sha256_file(Path(__file__).resolve())},
        "sources": sources,
        "targets": targets,
        "runtime_resolution_contract": {
            "entry_rsp_source": "target-pre-instruction-cpu-context",
            "entry_rsp_platform_fixture": "NOT_RUN",
            "return_address_source": "safe-read-[entry_rsp]",
            "resolve_by": "decode-preceding-instruction-boundary-in-containing-native-code",
            "fixed_subtract_forbidden": True,
            "tail_calls_need_terminal_branch_evidence": True,
            "unresolved_return_address_result": "observed_return_address-only",
        },
        "summary": {
            "targets": len(targets),
            "targets_with_verified_direct_static_site": covered,
            "targets_without_verified_direct_static_site": len(targets) - covered,
            "verified_direct_sites": sum(target["direct_static_site_count"] for target in targets),
            "verified_direct_calls": totals["call"],
            "verified_direct_jumps": totals["jmp"],
            "static_direct_sites_are_all_runtime_callers": False,
        },
    }
    validate_callsite_manifest(manifest)
    return manifest


def write_report(path: Path, exit_manifest: dict, callsite_manifest: dict):
    e = exit_manifest["summary"]
    c = callsite_manifest["summary"]
    lines = [
        "# P1 静态出口与 callsite 机械候选报告",
        "",
        "本报告只使用固定哈希的本地游戏 PE、v6 有来源观察点和 Capstone 指令边界。",
        "当前状态不是三方验证，不可用于生成正式游戏激活配置。",
        "",
        f"- 目标函数：{e['target_functions']}；精确 `.pdata` 入口：{e['exact_pdata_entries']}。",
        f"- 有可达 ret 候选的函数：{e['functions_with_reachable_ret_candidates']}；ret 候选：{e['reachable_ret_candidates']}。",
        f"- 具有至少一个 5 字节纯 epilogue 候选的函数：{e['functions_with_minimum_5_byte_pure_epilogue_candidate']}。",
        f"- 经 Capstone 验证的直接 call/jmp：{c['verified_direct_sites']}；覆盖 {c['targets_with_verified_direct_static_site']}/{c['targets']} 个目标。",
        "",
        "## 尚未晋升的原因",
        "",
        "- 尚未联接 Ghidra CFG、cold fragment、EH funclet 和全部入边。",
        "- 尚未运行固定 Gum 构建的 relocator dry-run，因此没有 `backend_patch_contract`。",
        "- 尚未验证 relocated span 内 fault、CET/CFG 和入口 architectural RSP。",
        "- 静态直接引用不覆盖虚调用、接口、委托、Task、Job/ECS 等间接分派。",
        "",
        "任何缺口都保持显式 UNKNOWN；平台产物不等于控制器闭合。",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(plan_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"P1 evidence directory is immutable: {output}")
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    module_paths = {alias: source_path(plan, module["image"], module["sha256"])
                    for alias, module in plan["modules"].items()}
    needed = {point["module"] for point in plan["points"] if point["backend"] == "gum_probe"}
    images = {alias: NativePE(module_paths[alias]) for alias in needed}
    output.mkdir(parents=True)
    sources = [
        {"kind": "capture-plan", "path": str(plan_path.resolve()), "sha256": sha256_file(plan_path)},
        *({"kind": "module", "alias": alias, "path": str(module_paths[alias]),
           "sha256": sha256_file(module_paths[alias])} for alias in sorted(needed)),
        {"kind": "backend-build", "path": str(GUM_LIB.resolve()), "sha256": sha256_file(GUM_LIB)},
    ]
    exit_manifest, ghidra_targets = build_exit_manifest(plan, images, sources)
    callsite_manifest = build_callsite_manifest(plan, images, sources)
    write_json(output / "native-exit-manifest.candidate.json", exit_manifest)
    write_json(output / "native-callsite-manifest.candidate.json", callsite_manifest)
    write_json(output / "ghidra-targets.json", {
        "schema": "uc.ghidra-target-list.v1", "status": "PENDING_GHIDRA_EXPORT",
        "targets": ghidra_targets, "sources": sources,
    })
    unique_ghidra = {}
    for target in ghidra_targets:
        key = (target["module"], target["function_id"], target["entry_rva"],
               target["runtime_function_begin_rva"], target["runtime_function_end_rva"])
        unique_ghidra[key] = target
    with (output / "ghidra-targets.tsv").open("w", encoding="utf-8", newline="\n") as stream:
        stream.write("module\tfunction_id_base64\tentry_rva\truntime_begin_rva\truntime_end_rva\trole_candidate\tseed_rvas\n")
        for target in sorted(unique_ghidra.values(), key=lambda item: (item["module"], item["entry_rva"], item["runtime_function_begin_rva"])):
            encoded = base64.b64encode(target["function_id"].encode("utf-8")).decode("ascii")
            stream.write(f"{target['module']}\t{encoded}\t{target['entry_rva']}\t{target['runtime_function_begin_rva']}\t"
                         f"{target['runtime_function_end_rva']}\t{target['role_candidate']}\t"
                         f"{','.join(map(str, target['seed_rvas']))}\n")
    write_report(output / "report.md", exit_manifest, callsite_manifest)
    inventory = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            inventory.append({"file": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)})
    write_json(output / "evidence-index.json", {
        "schema": "uc.p1-evidence-index.v1", "files": inventory,
        "activation_ready": False, "game_runtime_required": False,
    })
    print(json.dumps({
        "output": str(output),
        "exit_summary": exit_manifest["summary"],
        "callsite_summary": callsite_manifest["summary"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.plan.resolve(), args.out.resolve())
