"""Bind exit candidates to immutable file-backed source prefixes.

This pass does not promote indirect-edge completeness, terminal semantics, or
game patch contracts.  It only separates the semantic epilogue window from a
longer source-identity prefix and records the own-fixture relocation scope.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import json
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest


PREFIX_BYTES = 32
QUALIFIED_CLASSES = ("nop", "stack-adjust", "nonvolatile-pop", "ret")


def source_map(manifest: dict) -> dict[str, Path]:
    result = {}
    for source in manifest.get("sources", []):
        if source.get("kind") == "module":
            path = Path(source["path"]).resolve()
            if file_hash(path) != source["sha256"]:
                raise ValueError(f"module changed: {path}")
            result[source["alias"]] = path
    return result


def run(manifest_path: Path, capability_path: Path, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(manifest)
    capability = json.loads(capability_path.read_text(encoding="utf-8-sig"))
    classes = capability.get("pure_epilogue_instruction_classes", {})
    if classes.get("near_redirect_relocation") != "passed-own-fixture" or \
            tuple(classes.get("classes", [])) != QUALIFIED_CLASSES:
        raise ValueError("backend capability lacks exact pure-epilogue class qualification")
    modules = {alias: NativePE(path) for alias, path in source_map(manifest).items()}
    value = copy.deepcopy(manifest)
    value["generated_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    value["generator"] = {"name": Path(__file__).name, "sha256": file_hash(Path(__file__))}
    value["backend_capability"]["sealed_artifact"] = {
        "path": str(capability_path), "sha256": file_hash(capability_path)}
    value["backend_capability"]["pure_epilogue_instruction_classes"] = copy.deepcopy(classes)
    candidates = 0
    long_candidates = 0
    for function in value["functions"]:
        pe = modules[function["module"]]
        if file_hash(pe.path) != function["module_sha256"]:
            raise ValueError(f"function/module identity mismatch: {function['function_id']}")
        for exit_site in function.get("normal_exits", []):
            for candidate in exit_site.get("probe_candidates", []):
                semantic = bytes.fromhex(candidate["expected_bytes"])
                prefix = pe.bytes_at(candidate["probe_rva"], PREFIX_BYTES)
                if not prefix.startswith(semantic):
                    raise ValueError(f"semantic/source mismatch at {candidate['probe_rva']:#x}")
                candidate["verified_source_prefix"] = prefix.hex()
                candidate["source_identity"] = {
                    "kind": "file-backed-pe-bytes", "module_sha256": function["module_sha256"],
                    "probe_rva": candidate["probe_rva"], "length": PREFIX_BYTES}
                candidate["relocation_qualification"] = {
                    "instruction_classes": list(QUALIFIED_CLASSES),
                    "near_5_byte": "passed-own-fixture",
                    "far_16_byte": "not-observed-target-runtime-required",
                    "game_site_patch_contract": "not-run"}
                candidates += 1
                if candidate.get("available_span_through_ret", 0) >= 16:
                    long_candidates += 1
    value["summary"]["source_identity_bound_candidates"] = candidates
    value["summary"]["candidates_semantically_safe_for_16_byte_redirect"] = long_candidates
    value["summary"]["backend_patch_contracts_assigned"] = 0
    value["summary"]["incoming_indirect_edges_proven_complete"] = 0
    value["summary"]["game_runtime_verified"] = False
    output.mkdir(parents=True)
    destination = output / "native-exit-manifest.source-bound.json"
    destination.write_bytes(canonical(value))
    index = {
        "schema": "uc.source-bound-exit-index.v1", "sealed": True,
        "activation_ready": False, "game_runtime_verified": False,
        "inputs": [
            {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
            {"path": str(capability_path), "sha256": file_hash(capability_path)},
            {"path": str(Path(__file__).resolve()), "sha256": file_hash(Path(__file__))}],
        "files": [{"path": str(destination), "sha256": file_hash(destination),
                   "bytes": destination.stat().st_size}]}
    (output / "evidence-index.json").write_bytes(canonical(index))
    print(json.dumps({"output": str(output), "manifest": str(destination),
                      "sha256": file_hash(destination), "candidates": candidates,
                      "safe_for_16": long_candidates, "activation_ready": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--capability", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.capability.resolve(), args.out.resolve())
