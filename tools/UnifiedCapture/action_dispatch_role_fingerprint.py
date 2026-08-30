"""Mechanically classify an unlabelled action pair from native code shape.

The classifier only promotes a role when the complete declared .pdata range has
the same mnemonic/size sequence as one or more source-labelled reference
methods, and every matching reference agrees on the role.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash
from uc.native_manifest import NativePE


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _fingerprint(pe: NativePE, rva: int) -> dict[str, Any]:
    runtime = pe.by_start.get(rva)
    if runtime is None:
        raise ValueError(f"method RVA has no exact .pdata entry: {rva:#x}")
    decoded = pe.decode(runtime)
    if not decoded["all_declared_bytes_decoded"]:
        raise ValueError(f"method .pdata range did not decode completely: {rva:#x}")
    shape = [[ins["mnemonic"], ins["size"]] for ins in decoded["instructions"]]
    raw = pe.bytes_at(runtime.begin, runtime.end - runtime.begin)
    calls = [{"site_rva": ins["rva"], "mnemonic": ins["mnemonic"],
              "target_rva": ins["direct_target_rva"]}
             for ins in decoded["instructions"]
             if "call" in ins["groups"] or ins["mnemonic"] == "jmp"]
    return {"rva": rva, "end_rva": runtime.end, "unwind_rva": runtime.unwind_rva,
            "instruction_count": len(shape), "all_declared_bytes_decoded": True,
            "mnemonic_size_shape": shape,
            "shape_sha256": hashlib.sha256(canonical(shape)).hexdigest(),
            "body_sha256": hashlib.sha256(raw).hexdigest(), "direct_control_transfers": calls}


def _classify(target: dict[str, Any], references: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [row for row in references if row["fingerprint"]["shape_sha256"] == target["shape_sha256"]]
    roles = sorted({row["role"] for row in matches})
    return {"status": "STRUCTURALLY_CLASSIFIED" if len(roles) == 1 and matches else "UNRESOLVED",
            "derived_role": roles[0] if len(roles) == 1 and matches else None,
            "matching_source_references": [{"serialized_type": row["serialized_type"],
                "method": row["method"], "role": row["role"], "rva": row["fingerprint"]["rva"],
                "shape_sha256": row["fingerprint"]["shape_sha256"]} for row in matches],
            "matching_roles": roles}


def run(pe_path: Path, inventory_path: Path, target_type: str, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    inventory = _load(inventory_path)
    rows = {row["serializedType"]: row for row in inventory.get("nativeTypeLedger", [])}
    target_row = rows.get(target_type)
    if target_row is None:
        raise ValueError(f"target type is absent: {target_type}")
    pe = NativePE(pe_path)
    references = []
    for type_name, row in rows.items():
        dispatch = row.get("nativeIdentityAndDispatch", {}).get("dispatch")
        if not isinstance(dispatch, dict):
            continue
        for role, key in (("wrapper", "wrapper"), ("nativeImplementation", "nativeImplementation")):
            method = dispatch.get(key)
            if method:
                references.append({"serialized_type": type_name, "method": method["name"],
                    "role": role, "fingerprint": _fingerprint(pe, int(method["rva"]))})

    target_methods = {row["name"]: row for row in
                      target_row.get("nativeIdentityAndDispatch", {}).get("methods", [])}
    classifications = []
    for method_name in ("HCBMKBDIHJB", "BHCIJGGHECM"):
        method = target_methods.get(method_name)
        if not method:
            raise ValueError(f"target type misses method {method_name}")
        fingerprint = _fingerprint(pe, int(method["rva"]))
        classifications.append({"method": method_name, "fingerprint": fingerprint,
                                **_classify(fingerprint, references)})
    assigned = {row["derived_role"] for row in classifications if row["derived_role"]}
    checks = {"both_members_classified": all(row["status"] == "STRUCTURALLY_CLASSIFIED"
                                               for row in classifications),
              "roles_are_distinct": assigned == {"wrapper", "nativeImplementation"},
              "all_target_ranges_fully_decoded": all(row["fingerprint"]["all_declared_bytes_decoded"]
                                                       for row in classifications)}
    result = {"schema": "uc.action-dispatch-role-fingerprint.v1", "target_type": target_type,
        "sources": {"pe": {"path": str(pe_path), "sha256": file_hash(pe_path)},
                    "inventory": {"path": str(inventory_path), "sha256": file_hash(inventory_path)}},
        "reference_role_count": len(references), "classifications": classifications, "checks": checks,
        "bounded_conclusion": "target role assignment is a mechanical derivation from complete .pdata code-shape equality to source-labelled references",
        "not_proven": ["runtime branch selection", "wrapper-to-native fallback semantics",
                       "semantic equivalence beyond the compared complete mnemonic/size sequence",
                       "complete controller"]}
    if not all(checks.values()):
        raise ValueError(f"dispatch classification checks failed: {checks}")
    output.mkdir(parents=True)
    artifact = output / "action-dispatch-role-fingerprint.json"
    artifact.write_bytes(canonical(result))
    report = {"schema": "uc.action-dispatch-role-fingerprint-report.v1",
              "artifact": {"path": str(artifact), "sha256": file_hash(artifact)},
              "target_type": target_type, "assignments": {row["method"]: row["derived_role"]
                  for row in classifications}, **checks}
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--target-type", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.pe.resolve(), args.inventory.resolve(), args.target_type, args.out.resolve())
