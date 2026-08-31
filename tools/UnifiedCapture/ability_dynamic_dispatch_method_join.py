"""Join observed dynamic target RVAs to preserved native method catalogs.

An exact RVA match identifies a catalogued method body.  It does not by itself
rename an observed runtime class, prove object lifetime, or turn an unobserved
callsite into an executed edge.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def build_catalog(execution_truth: dict[str, Any], upstream_types: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    catalog: dict[int, list[dict[str, Any]]] = defaultdict(list)
    if execution_truth.get("schema") != "zzz.remielle.origin-controller-execution-truth.v1":
        raise ValueError("unsupported controller execution truth")
    for row in execution_truth.get("nativeTypeTable", []):
        for method in row.get("dispatch", {}).get("operationalMethods", []):
            if method.get("rva") is None:
                continue
            catalog[int(method["rva"])].append({
                "source": "remielle_controller_execution_truth",
                "declaring_semantic_type": row.get("semanticType"),
                "declaring_config_class": row.get("configClass"),
                "declaring_role": row.get("role"),
                "method_name": method.get("name"),
                "signature": method.get("signature", []),
            })
    if not isinstance(upstream_types, list):
        raise ValueError("upstream native types must be a list")
    for row in upstream_types:
        for method in row.get("methods", []):
            if method.get("rva") is None:
                continue
            candidate = {
                "source": "persistent_upstream_native_types",
                "declaring_native_type": row.get("nativeName"),
                "declaring_semantic_type": row.get("semanticType"),
                "type_index": row.get("typeIndex"),
                "method_name": method.get("name"),
                "signature": method.get("signature", []),
            }
            if candidate not in catalog[int(method["rva"])]:
                catalog[int(method["rva"])].append(candidate)
    return dict(catalog)


def join(runtime: dict[str, Any], catalog: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    if runtime.get("schema") != "uc.ability-dynamic-dispatch-runtime-analysis.v1":
        raise ValueError("unsupported runtime dynamic-dispatch analysis")
    target_rvas = sorted({
        int(target["rva"])
        for site in runtime["dynamic_sites"]
        for target in site.get("targets", [])
        if target.get("classification") == "GAME_MODULE_RVA"
    })
    targets = [{"target_rva": rva,
                "catalog_status": "EXACT_METHOD_BODY_MATCH" if rva in catalog else "NO_CATALOG_MATCH",
                "method_candidates": catalog.get(rva, [])}
               for rva in target_rvas]
    pairs = []
    for site in runtime["dynamic_sites"]:
        for pair in site.get("class_target_pairs", []):
            target = pair["target"]
            if target.get("classification") != "GAME_MODULE_RVA":
                matches = []
                status = "TARGET_OUTSIDE_GAME_MODULE"
            else:
                matches = catalog.get(int(target["rva"]), [])
                status = "EXACT_METHOD_BODY_MATCH" if matches else "NO_CATALOG_MATCH"
            pairs.append({"point": site["point"], "observed_class_name": pair["class_name"],
                          "target": target, "count": int(pair["count"]),
                          "catalog_status": status, "method_candidates": matches})
    return {"targets": targets, "observed_class_target_pairs": pairs,
            "summary": {"observed_game_target_rvas": len(targets),
                        "exact_catalogued_method_targets": sum(bool(row["method_candidates"]) for row in targets),
                        "uncatalogued_method_targets": sum(not row["method_candidates"] for row in targets),
                        "observed_class_target_pairs": len(pairs)}}


def analyze(runtime_path: Path, execution_truth_path: Path, upstream_types_path: Path,
            output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    runtime = _load(runtime_path)
    truth = _load(execution_truth_path)
    upstream = _load(upstream_types_path)
    result = {
        "schema": "uc.ability-dynamic-dispatch-method-join.v1",
        "sources": {"runtime_analysis": _source(runtime_path),
                    "controller_execution_truth": _source(execution_truth_path),
                    "persistent_upstream_native_types": _source(upstream_types_path)},
        "bounded_conclusions": [
            "exact RVA matches identify preserved native method bodies",
            "runtime class names remain observed class evidence and are not renamed from method catalogs",
            "missing catalog entries remain unresolved and are not guessed",
        ],
        **join(runtime, build_catalog(truth, upstream)),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(result))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_analysis", type=Path)
    parser.add_argument("controller_execution_truth", type=Path)
    parser.add_argument("upstream_native_types", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.runtime_analysis, args.controller_execution_truth,
                         args.upstream_native_types, args.output)
    except Exception as error:
        write_failure(args.output, "ability_dynamic_dispatch_method_join", error, {
            "runtime_analysis": str(args.runtime_analysis),
            "controller_execution_truth": str(args.controller_execution_truth),
            "upstream_native_types": str(args.upstream_native_types)})
        raise
    print(json.dumps({"ok": True, "output": str(args.output.resolve()),
                      **result["summary"]}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    run_main(main)
