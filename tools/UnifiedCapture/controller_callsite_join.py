"""Join controller entry return-address evidence to harvested GameAssembly methods."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _parse_catalog(path: Path) -> dict[int, list[dict[str, Any]]]:
    classes: dict[str, str] = {}
    methods: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        fields = line.split("|")
        if len(fields) >= 5 and fields[0] == "CLASS":
            classes[fields[1]] = fields[4]
        elif len(fields) >= 6 and fields[0] == "METHOD":
            try:
                rva = int(fields[4], 0)
            except ValueError:
                continue
            signature = fields[6:]
            methods[rva].append({"owner": classes.get(fields[1], fields[1]), "method": fields[3],
                "ordinal": int(fields[2]), "rva": rva, "signature": signature,
                "source": str(path), "source_line": line_number})
    return methods


def run(analysis_path: Path, catalogs: list[Path], output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    analysis = _load(analysis_path)
    identities: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for catalog in catalogs:
        for rva, rows in _parse_catalog(catalog).items():
            identities[rva].extend(rows)
    rows = []
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    identified = 0
    for evidence in analysis["runtime_callsites"]:
        begin = int(evidence["caller_runtime_function"]["begin_rva"])
        matches = identities.get(begin, [])
        # Different harvested files can repeat the same authoritative method.
        unique = {}
        for match in matches:
            key = (match["owner"], match["method"], match["ordinal"], match["rva"], tuple(match["signature"]))
            unique.setdefault(key, match)
        matches = list(unique.values())
        if matches:
            identified += 1
        row = {"callee_point": evidence["point"], "callsite_rva": int(evidence["callsite_rva"]),
            "call_kind": evidence["call_kind"], "observation_count": int(evidence["event_count"]),
            "caller_runtime_function": evidence["caller_runtime_function"],
            "caller_method_identities": matches,
            "identity_status": "SOURCE_IDENTIFIED" if matches else "UNRESOLVED"}
        rows.append(row)
        key = (begin, evidence["point"])
        group = groups.setdefault(key, {"caller_begin_rva": begin, "callee_point": evidence["point"],
            "caller_method_identities": matches, "callsites": [], "observation_count": 0,
            "call_kinds": set()})
        group["callsites"].append(int(evidence["callsite_rva"]))
        group["observation_count"] += int(evidence["event_count"])
        group["call_kinds"].add(evidence["call_kind"])
    edges = []
    for key in sorted(groups):
        group = dict(groups[key])
        group["callsites"] = sorted(set(group["callsites"]))
        group["call_kinds"] = sorted(group["call_kinds"])
        group["evidence"] = "runtime return address + unique decoded predecessor call + exact harvested caller method RVA"
        edges.append(group)
    result = {"schema": "uc.controller-runtime-caller-join.v1",
        "sources": {"runtime-analysis": {"path": str(analysis_path), "sha256": file_hash(analysis_path)},
                    "method-catalogs": [{"path": str(path), "sha256": file_hash(path)} for path in catalogs]},
        "runtime_callsite_rows": rows, "runtime_edges": edges,
        "summary": {"runtime_callsite_rows": len(rows), "source_identified_rows": identified,
                    "unresolved_rows": len(rows) - identified, "runtime_edges": len(edges)},
        "not_proven": ["semantic meaning of obfuscated caller methods", "object or entity identity",
                       "cross-thread causality", "per-move attribution", "complete controller"]}
    output.mkdir(parents=True)
    artifact = output / "controller-runtime-caller-join.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.controller-runtime-caller-join-report.v1",
              "artifact": {"path": str(artifact), "sha256": file_hash(artifact)}, **result["summary"]}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.analysis.resolve(), [path.resolve() for path in args.catalog], args.out.resolve())
