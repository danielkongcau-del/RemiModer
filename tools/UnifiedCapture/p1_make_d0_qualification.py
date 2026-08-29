"""Create a source-bound D0 site-qualification request for one real function."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE, validate_exit_manifest


def run(manifest_path: Path, function_id: str, output: Path):
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    validate_exit_manifest(manifest)
    functions = [row for row in manifest["functions"] if row["function_id"] == function_id]
    if len(functions) != 1:
        raise ValueError("function id is not unique")
    function = functions[0]
    sources = {row["alias"]: row for row in manifest["sources"] if row.get("kind") == "module"}
    source = sources[function["module"]]
    image = NativePE(Path(source["path"]))
    if file_hash(image.path) != function["module_sha256"]:
        raise ValueError("module identity changed")
    entry_rva = function["entry_rva"]
    entry_prefix = image.bytes_at(entry_rva, 32)
    span = 0
    entry_instructions = []
    for ins in image.cs.disasm(entry_prefix, image.image_base + entry_rva):
        entry_instructions.append({"rva": ins.address-image.image_base, "size": ins.size,
                                   "mnemonic": ins.mnemonic, "operands": ins.op_str})
        span += ins.size
        if span >= 16:
            break
    if span < 16:
        raise ValueError("entry lacks a 16-byte instruction-boundary window")
    entry_edges = image.direct_control_xrefs(set(range(entry_rva + 1, entry_rva + span)))
    if entry_edges:
        raise ValueError("direct control-flow edge enters entry qualification window")
    candidates = []
    for exit_site in function["normal_exits"]:
        for candidate in exit_site["probe_candidates"]:
            if candidate["available_span_through_ret"] >= 16 and candidate.get("direct_interior_edge_free"):
                candidates.append((exit_site, candidate))
    if not candidates:
        raise ValueError("function has no 16-byte direct-edge-free exit qualification window")
    exit_site, candidate = sorted(candidates, key=lambda row: (row[1]["available_span_through_ret"],
                                                                row[1]["probe_rva"]))[0]
    qualification = {"schema": "uc.probe-site-qualification.v1",
        "qualification_id": "d0-real-pair-" + function_id,
        "modules": {function["module"]: {"image": Path(source["path"]).name,
                                            "sha256": function["module_sha256"]}},
        "sites": [
            {"id": function_id + "/entry", "module": function["module"], "rva": entry_rva,
             "verified_source_prefix": entry_prefix.hex(), "semantic_safe_span": span,
             "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True,
             "static_evidence": {"instruction_boundary_span": span, "instructions": entry_instructions,
                                 "direct_edge_scan_scope": "all-file-backed-executable-sections",
                                 "direct_interior_edges": []}},
            {"id": function_id + "/" + exit_site["exit_site_id"], "module": function["module"],
             "rva": candidate["probe_rva"], "verified_source_prefix": candidate["verified_source_prefix"],
             "semantic_safe_span": candidate["available_span_through_ret"],
             "safe_redirect_spans": [5, 16], "direct_interior_edge_free": True,
             "static_evidence": {"terminal_semantics_verified": exit_site["terminal_semantics_verified"],
                                 "semantic_exit_bytes": candidate["expected_bytes"],
                                 "instruction_rvas": candidate["instruction_rvas"],
                                 "direct_edge_scan_scope": candidate["direct_edge_scan_scope"],
                                 "incoming_indirect_edges_complete": False}}]}
    output.mkdir(parents=True)
    request = output / "qualification.json"
    request.write_bytes(canonical(qualification))
    report = {"schema": "uc.d0-qualification-preparation.v1", "activation_ready": False,
              "game_runtime_verified": False, "behavior_capture": False,
              "function_id": function_id, "selected_exit_site_id": exit_site["exit_site_id"],
              "request": {"path": str(request), "sha256": file_hash(request)},
              "source_manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
              "remaining_after_qualification": ["terminal/completeness promotion if pair capture is required",
                                                  "incoming indirect-edge scope remains explicit",
                                                  "behavior invocation and ABI interpretation"]}
    report_path = output / "report.json"
    report_path.write_bytes(canonical(report))
    print(json.dumps({"output": str(output), "request": str(request), "sha256": file_hash(request),
                      "function_id": function_id, "entry_safe_span": span,
                      "exit_safe_span": candidate["available_span_through_ret"],
                      "activation_ready": False}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--function-id", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(), args.function_id, args.out.resolve())
