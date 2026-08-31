"""Cross-check prioritized caller decodes with a targeted Ghidra export."""
from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _export(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    metadata = {}
    data = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.startswith("#"):
            key, value = line[1:].split("\t", 1)
            metadata[key] = value
        else:
            data.append(line)
    return metadata, list(csv.DictReader(io.StringIO("\n".join(data)), delimiter="\t"))


def _mnemonic(value: str) -> str:
    # Capstone and Ghidra choose different canonical spellings for the same
    # x86 condition-code encodings.  Byte equality remains mandatory.
    value = value.lower()
    return {"jz": "je", "jnz": "jne", "setnz": "setne", "jc": "jb"}.get(value, value)


def build(static: dict[str, Any], metadata: dict[str, str],
          exported: list[dict[str, str]]) -> dict[str, Any]:
    groups: dict[int, list[dict[str, str]]] = {}
    for row in exported:
        groups.setdefault(int(row["runtime_begin_rva"]), []).append(row)
    output = []
    for function in static.get("functions", []):
        begin, end = int(function["begin_rva"]), int(function["end_rva"])
        rows = groups.get(begin, [])
        capstone = {int(row["rva"]): row for row in function["instructions"]}
        ghidra = {int(row["instruction_rva"]): row for row in rows}
        missing = sorted(set(capstone) - set(ghidra))
        extra = sorted(set(ghidra) - set(capstone))
        disagreements = []
        for rva in sorted(set(capstone) & set(ghidra)):
            left, right = capstone[rva], ghidra[rva]
            if left["bytes"].lower() != right["bytes"].lower() or \
                    _mnemonic(left["mnemonic"]) != _mnemonic(right["mnemonic"]):
                disagreements.append({"rva": rva, "capstone": {
                    "bytes": left["bytes"], "mnemonic": left["mnemonic"]},
                    "ghidra": {"bytes": right["bytes"], "mnemonic": right["mnemonic"]}})
        references = sorted({int(value) for row in rows
            for value in row.get("incoming_reference_rvas", "").split(",") if value})
        output.append({"module": function["module"], "begin_rva": begin, "end_rva": end,
            "capstone_instruction_count": len(capstone),
            "ghidra_instruction_count": len(ghidra),
            "missing_instruction_rvas": missing,
            "extra_instruction_rvas": extra,
            "instruction_disagreements": disagreements,
            "instruction_agreement": not missing and not extra and not disagreements,
            "incoming_reference_rvas": references,
            "external_incoming_reference_rvas": [rva for rva in references
                                                   if not begin <= rva < end],
        })
    return {"functions": output, "summary": {
        "functions": len(output),
        "instruction_agreement_functions": sum(row["instruction_agreement"] for row in output),
        "capstone_instructions": sum(row["capstone_instruction_count"] for row in output),
        "ghidra_instructions": sum(row["ghidra_instruction_count"] for row in output),
        "external_incoming_references": sum(len(row["external_incoming_reference_rvas"])
                                              for row in output),
    }, "ghidra_program": metadata}


def derive(static_path: Path, ghidra_path: Path, output: Path) -> dict[str, Any]:
    static_path, ghidra_path, output = (Path(value).resolve()
                                        for value in (static_path, ghidra_path, output))
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    static = _load(static_path)
    metadata, exported = _export(ghidra_path)
    expected_hashes = {row["sha256"] for row in
                       static.get("sources", {}).get("module_images", {}).values()}
    if metadata.get("schema") != "uc.ghidra-probe-export.v1" or \
            metadata.get("executable_sha256", "").lower() not in expected_hashes:
        raise ValueError("Ghidra program identity differs from source-bound module")
    analysis = build(static, metadata, exported)
    if analysis["summary"]["instruction_agreement_functions"] != analysis["summary"]["functions"]:
        raise ValueError("Ghidra and Capstone priority-caller instructions disagree")
    document = {"schema": "uc.caller-candidate-ghidra-join.v1",
        "sources": {
            "static_decode": {"path": str(static_path), "sha256": file_hash(static_path)},
            "ghidra_export": {"path": str(ghidra_path), "sha256": file_hash(ghidra_path)},
        }, **analysis,
        "semantic_limits": [
            "Incoming references include unwind, exception, relocation, or other metadata references.",
            "Instruction agreement does not provide a semantic function name.",
            "No caller is attributed to a move, entity, or character by this join.",
        ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(canonical(document) + b"\n")
    result = {"ok": True, "output": str(output), **document["summary"]}
    print(json.dumps(result, ensure_ascii=False))
    return result


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return derive(args.static, args.ghidra, args.out)


if __name__ == "__main__":
    run_main(main)
