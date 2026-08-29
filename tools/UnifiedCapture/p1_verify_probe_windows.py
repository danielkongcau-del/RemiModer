"""Verify direct incoming edges and candidate-window overlap for P1 manifests."""
from __future__ import annotations

import argparse
import copy
import json
from collections import defaultdict
from pathlib import Path

from uc.native_manifest import NativePE, sha256_file, validate_exit_manifest


def module_paths(manifest: dict):
    result = {}
    for source in manifest["sources"]:
        if source.get("kind") == "module":
            path = Path(source["path"]).resolve()
            if sha256_file(path) != source["sha256"]:
                raise ValueError(f"module changed: {path}")
            result[source["alias"]] = path
    return result


def run(source: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"window verification output is immutable: {output}")
    original = json.loads(source.read_text(encoding="utf-8-sig"))
    value = copy.deepcopy(original)
    images = {alias: NativePE(path) for alias, path in module_paths(value).items()}
    candidates_by_module = defaultdict(list)
    target_bytes_by_module = defaultdict(set)
    for function in value["functions"]:
        for exit_site in function["normal_exits"]:
            for candidate in exit_site["probe_candidates"]:
                identity = {
                    "function_id": function["function_id"], "exit_site_id": exit_site["exit_site_id"],
                    "module": function["module"], "minimum_span_class": candidate["candidate_for_minimum_span"],
                    "probe_rva": candidate["probe_rva"], "span": candidate["available_span_through_ret"],
                }
                candidates_by_module[function["module"]].append((identity, candidate))
                start = candidate["probe_rva"]
                target_bytes_by_module[function["module"]].update(range(start + 1, start + candidate["available_span_through_ret"]))
    xrefs_by_module = {}
    for module, targets in target_bytes_by_module.items():
        xrefs_by_module[module] = images[module].direct_control_xrefs(targets)
    partial_overlaps = []
    exact_shared = []
    backend_span_alternatives = []
    for module, candidates in candidates_by_module.items():
        direct_by_target = defaultdict(list)
        for xref in xrefs_by_module[module]:
            direct_by_target[xref["target_rva"]].append(xref)
        for identity, candidate in candidates:
            start = candidate["probe_rva"]
            end = start + candidate["available_span_through_ret"]
            edges = [edge for target in range(start + 1, end) for edge in direct_by_target[target]]
            candidate["direct_interior_edges"] = edges
            candidate["direct_interior_edge_free"] = not edges
            candidate["direct_edge_scan_scope"] = "all-file-backed-executable-sections; pdata+Capstone-boundary-verified"
            candidate["incoming_edges_complete"] = False
        for index, (left_id, left) in enumerate(candidates):
            left_range = (left["probe_rva"], left["probe_rva"] + left["available_span_through_ret"])
            for right_id, right in candidates[index + 1:]:
                right_range = (right["probe_rva"], right["probe_rva"] + right["available_span_through_ret"])
                if left_range[1] <= right_range[0] or right_range[1] <= left_range[0]:
                    continue
                record = {"module": module, "left": left_id, "right": right_id,
                          "left_range": list(left_range), "right_range": list(right_range)}
                if (left_id["function_id"], left_id["exit_site_id"]) == (right_id["function_id"], right_id["exit_site_id"]):
                    backend_span_alternatives.append(record)
                    continue
                if left_range == right_range and left["expected_bytes"] == right["expected_bytes"]:
                    exact_shared.append(record)
                else:
                    partial_overlaps.append(record)
    value["sources"].append({"kind": "probe-window-verifier", "path": str(Path(__file__).resolve()),
                             "sha256": sha256_file(Path(__file__).resolve())})
    value["summary"]["probe_candidates_checked_for_direct_interior_edges"] = sum(len(rows) for rows in candidates_by_module.values())
    value["summary"]["probe_candidates_with_direct_interior_edge"] = sum(
        bool(candidate["direct_interior_edges"]) for rows in candidates_by_module.values() for _, candidate in rows)
    value["summary"]["exact_shared_physical_window_candidates"] = len(exact_shared)
    value["summary"]["partial_overlap_candidates"] = len(partial_overlaps)
    value["summary"]["same_exit_backend_span_alternative_pairs"] = len(backend_span_alternatives)
    validate_exit_manifest(value)
    output.mkdir(parents=True)
    manifest_path = output / "native-exit-manifest.window-verified.json"
    manifest_path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ownership = {
        "schema": "uc.physical-probe-site-candidates.v1",
        "status": "backend-dry-run-pending",
        "identity": ["module_load_identity", "rva", "backend_build_hash", "patch_contract", "expected_bytes"],
        "exact_same_physical_site": "share-one-listener-multiple-logical-subscriptions",
        "partial_overlap": "reject",
        "same_logical_exit_span_alternatives": "backend-selects-one-after-dry-run",
        "exact_shared_candidates": exact_shared,
        "partial_overlap_candidates": partial_overlaps,
        "backend_span_alternative_pairs": backend_span_alternatives,
    }
    (output / "physical-probe-site-candidates.json").write_text(
        json.dumps(ownership, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = [
        "# P1 probe window verification",
        "",
        f"- 候选窗口：{value['summary']['probe_candidates_checked_for_direct_interior_edges']}。",
        f"- 存在经指令边界验证的直接分支进入窗口内部：{value['summary']['probe_candidates_with_direct_interior_edge']}。",
        f"- 完全相同、可进入共享判定的候选对：{len(exact_shared)}。",
        f"- 部分重叠、必须拒绝的候选对：{len(partial_overlaps)}。",
        f"- 同一逻辑出口的 5/16 字节后端备选对：{len(backend_span_alternatives)}（dry-run 后只选一个）。",
        "- 间接入边仍保持 UNKNOWN；固定 Gum 构建的实际 patch span 尚未 dry-run。",
    ]
    (output / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    files = []
    for path in sorted(output.iterdir()):
        if path.is_file(): files.append({"file": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)})
    (output / "evidence-index.json").write_text(json.dumps({
        "schema": "uc.p1-window-verification-index.v1", "source": str(source.resolve()),
        "files": files, "sealed": True, "activation_ready": False,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "summary": value["summary"]}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.out.resolve())
