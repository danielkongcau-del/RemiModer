"""Convert an RDC to RenderDoc XML+ZIP and mechanically inventory its replay inputs.

This is a preflight, not a uc.d3d11-capture.v1 converter.  It proves that the
official capture contains structured D3D11 calls and every referenced binary
blob before target-specific attachment export and package conversion begin.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from uc.cli import run_main
from uc.model import canonical, file_hash


SCHEMA = "uc.renderdoc-xml-inventory.v1"


def _find_renderdoccmd(explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit.resolve()
    else:
        found = shutil.which("renderdoccmd")
        candidate = Path(found) if found else Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RenderDoc" / "renderdoccmd.exe"
    if not candidate.is_file():
        raise ValueError(f"renderdoccmd not found: {candidate}")
    return candidate


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                            timeout=120, creationflags=flags)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr or result.stdout}")
    return result


def _resource_id(element: ET.Element) -> int:
    text = (element.text or "").strip()
    if not text:
        raise ValueError("empty ResourceId in RenderDoc XML")
    return int(text, 10)


def analyze_export(xml_path: Path, zip_path: Path) -> dict:
    xml_path = Path(xml_path).resolve()
    zip_path = Path(zip_path).resolve()
    if not xml_path.is_file() or not zip_path.is_file():
        raise ValueError("RenderDoc XML+ZIP export is incomplete")

    buffer_references: dict[int, dict] = {}
    creation_rows = []
    chunk_rows = []
    created_ids: set[int] = set()
    referenced_ids: set[int] = set()
    category_counts = {key: 0 for key in ("create", "set", "update", "copy_resolve", "clear", "draw", "dispatch", "present", "internal")}
    draw_rows = []
    driver_name: str | None = None
    chunk_serialization_version: int | None = None

    def process_chunk(chunk: ET.Element) -> None:
        name = chunk.get("name") or ""
        chunk_index = int(chunk.get("chunkIndex", "-1"))
        if name.startswith("Internal::"):
            category = "internal"
        elif "::Create" in name or "::GetClassInstance" in name:
            category = "create"
        elif "::Draw" in name:
            category = "draw"
        elif "::Dispatch" in name:
            category = "dispatch"
        elif "::Clear" in name:
            category = "clear"
        elif any(token in name for token in ("::Copy", "::Resolve", "::GenerateMips")):
            category = "copy_resolve"
        elif any(token in name for token in ("::UpdateSubresource", "::Map", "::Unmap")):
            category = "update"
        elif "::Present" in name:
            category = "present"
        elif "::" in name and name.rsplit("::", 1)[1].startswith(("IASet", "VSSet", "PSSet", "GSSet", "HSSet", "DSSet", "CSSet", "RSSet", "OMSet", "SOSet", "SetPredication")):
            category = "set"
        else:
            category = "internal"
        category_counts[category] += 1

        resources = []
        for element in chunk.iter("ResourceId"):
            identity = _resource_id(element)
            if identity:
                resources.append({"id": identity, "name": element.get("name"), "typename": element.get("typename")})
                referenced_ids.add(identity)
        if category == "create" and resources:
            output = resources[-1]
            created_ids.add(output["id"])
            creation_rows.append({"chunk_index": chunk_index, "call": name, "resource": output})

        buffers = []
        for element in chunk.iter("buffer"):
            text = (element.text or "").strip()
            if not text:
                raise ValueError(f"empty buffer index in chunk {chunk_index}")
            index = int(text, 10)
            length = int(element.get("byteLength", "-1"))
            if length < 0:
                raise ValueError(f"buffer lacks byteLength in chunk {chunk_index}")
            prior = buffer_references.get(index)
            if prior is not None and prior["size_bytes"] != length:
                raise ValueError(f"RenderDoc buffer {index} has inconsistent lengths")
            buffer_references.setdefault(index, {"index": index, "size_bytes": length, "uses": []})["uses"].append(
                {"chunk_index": chunk_index, "call": name, "name": element.get("name")})
            buffers.append(index)
        row = {"chunk_index": chunk_index, "chunk_id": int(chunk.get("id", "0")), "name": name,
               "category": category, "resource_ids": [item["id"] for item in resources], "buffer_indices": buffers}
        chunk_rows.append(row)
        if category == "draw":
            draw_rows.append(row)

    root_seen = False
    for event, element in ET.iterparse(xml_path, events=("start", "end")):
        if event == "start" and not root_seen:
            if element.tag != "rdc":
                raise ValueError("RenderDoc export root must be <rdc>")
            root_seen = True
        if event == "start" and element.tag == "chunks":
            chunk_serialization_version = int(element.get("version", "0"))
        elif event == "end" and element.tag == "driver":
            driver_name = (element.text or "").strip()
        elif event == "end" and element.tag == "chunk":
            process_chunk(element)
            element.clear()
    if driver_name != "D3D11":
        raise ValueError("only D3D11 RenderDoc exports are accepted")
    if chunk_serialization_version is None or not chunk_rows:
        raise ValueError("RenderDoc export lacks chunks")

    with zipfile.ZipFile(zip_path) as archive:
        names = set(archive.namelist())
        binary_rows = []
        for index, row in sorted(buffer_references.items()):
            member = f"{index:06d}"
            if member not in names:
                raise ValueError(f"RenderDoc ZIP lacks buffer member {member}")
            payload = archive.read(member)
            if len(payload) != row["size_bytes"]:
                raise ValueError(f"RenderDoc buffer {member} size mismatch")
            binary_rows.append({**row, "member": member, "sha256": hashlib.sha256(payload).hexdigest()})
        unreferenced_members = sorted(name for name in names if name.isdigit() and int(name) not in buffer_references)

    context_like = {row["resource"]["id"] for row in creation_rows
                    if row["resource"].get("typename") == "ID3D11DeviceContext *"}
    unresolved_ids = sorted(referenced_ids - created_ids - context_like)
    return {
        "driver": "D3D11",
        "chunk_serialization_version": chunk_serialization_version,
        "chunks": len(chunk_rows),
        "category_counts": category_counts,
        "created_objects": creation_rows,
        "draws": draw_rows,
        "binary_buffers": binary_rows,
        "unreferenced_binary_members": unreferenced_members,
        "referenced_resource_ids_without_create_chunk": unresolved_ids,
        "mechanical_checks": {
            "xml_parsed": True,
            "all_buffer_members_present_and_sized": True,
            "has_object_creation": bool(creation_rows),
            "has_pipeline_set_calls": category_counts["set"] > 0,
            "has_draw_or_dispatch": bool(draw_rows) or category_counts["dispatch"] > 0,
            "has_end_of_capture": any(row["name"] == "Internal::End of Capture" for row in chunk_rows),
        },
        "semantic_status": "mechanical-export-inventory-not-yet-uc-d3d11-package",
    }


def convert_and_inventory(rdc: Path, output: Path, renderdoccmd: Path | None = None) -> dict:
    rdc = Path(rdc).resolve()
    output = Path(output).resolve()
    if not rdc.is_file():
        raise ValueError(f"RDC missing: {rdc}")
    if output.exists():
        raise ValueError(f"output directory already exists: {output}")
    output.mkdir(parents=True)
    command = _find_renderdoccmd(renderdoccmd)
    version = _run([str(command), "version"]).stdout.strip()
    xml_path = output / "capture.zip.xml"
    _run([str(command), "convert", "-f", str(rdc), "-o", str(xml_path), "-c", "zip.xml"])
    zip_path = output / "capture.zip"
    inventory = analyze_export(xml_path, zip_path)
    report = {
        "schema": SCHEMA,
        "source": {"rdc_path": str(rdc), "rdc_sha256": file_hash(rdc), "renderdoc_version": version},
        "export": {"xml_path": xml_path.name, "xml_sha256": file_hash(xml_path),
                   "zip_path": zip_path.name, "zip_sha256": file_hash(zip_path)},
        **inventory,
    }
    (output / "inventory.json").write_bytes(canonical(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inventory a D3D11 RenderDoc capture through its lossless XML+ZIP export")
    parser.add_argument("rdc", type=Path)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--renderdoccmd", type=Path)
    args = parser.parse_args(argv)
    report = convert_and_inventory(args.rdc, args.output, args.renderdoccmd)
    summary = {"schema": report["schema"], "chunks": report["chunks"],
               "created_objects": len(report["created_objects"]), "draws": len(report["draws"]),
               "binary_buffers": len(report["binary_buffers"]), "checks": report["mechanical_checks"],
               "semantic_status": report["semantic_status"]}
    print(canonical(summary).decode("utf-8"))
    return report


if __name__ == "__main__":
    run_main(main)
