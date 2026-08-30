"""Enrich a controller frontier with source-verified field-level raw reads.

This tool never infers a controller implementation.  It verifies exact runtime
field-harvest and method-reflection records, checks the selected native job
wrapper instructions, then emits a new immutable CapturePlan plus a provenance
report.  Existing plans and evidence files are read-only inputs.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from uc.model import canonical, file_hash, validate
from uc.native_manifest import NativePE


TASK_LAYOUTS: dict[int, dict[str, Any]] = {
    34455: {
        "name": "SetBoolParameter",
        "fields": (
            ("target-game-object", 0x58, 8), ("shared-bool-object", 0x60, 8),
            ("parameter-name-object", 0x68, 8), ("animator-object", 0x70, 8),
            ("previous-game-object", 0x78, 8), ("parameter-hash", 0x80, 4),
            ("set-once", 0x84, 1),
        ),
        "methods": {"OnStart": 0x1F76E200, "OnUpdate": 0x1F76E390,
                    "OnReset": 0x1F76E830},
        "field_lines": (
            "public SharedGameObject targetGameObject; // 0x58",
            "public SharedBool boolValue; // 0x60",
            "public SharedString paramaterName; // 0x68",
            "private Animator animator; // 0x70",
            "private GameObject prevGameObject; // 0x78",
            "private int hashID; // 0x80",
            "public bool setOnce; // 0x84",
        ),
    },
    34459: {
        "name": "SetIntegerParameter",
        "fields": (
            ("target-game-object", 0x58, 8), ("shared-int-object", 0x60, 8),
            ("parameter-name-object", 0x68, 8), ("animator-object", 0x70, 8),
            ("previous-game-object", 0x78, 8), ("parameter-hash", 0x80, 4),
            ("set-once", 0x84, 1),
        ),
        "methods": {"OnStart": 0x1F835F50, "OnUpdate": 0x1F8360E0,
                    "OnReset": 0x1F836580},
        "field_lines": (
            "public SharedGameObject targetGameObject; // 0x58",
            "public SharedInt intValue; // 0x60",
            "public SharedString paramaterName; // 0x68",
            "private Animator animator; // 0x70",
            "private GameObject prevGameObject; // 0x78",
            "private int hashID; // 0x80",
            "public bool setOnce; // 0x84",
        ),
    },
    41564: {
        "name": "SetTriggerParameter",
        "fields": (
            ("animator-component", 0x58, 8), ("shared-owner-entity", 0x60, 8),
            ("parameter-name-object", 0x68, 8), ("owner-entity", 0x70, 8),
            ("parameter-hash", 0x78, 4),
        ),
        "methods": {"OnUpdate": 0x14A207B0, "OnReset": 0x14A20AC0},
        "field_lines": (
            "private OAFMFKKNHJA animatorComponent; // 0x58",
            "public SharedGameEntity SharedOwnerEntity; // 0x60",
            "public SharedString paramaterName; // 0x68",
            "private Entity ownerEntity; // 0x70",
            "private int hashID; // 0x78",
        ),
    },
    71227: {
        "name": "SetBoolParameter",
        "fields": (
            ("shared-bool-object", 0x58, 8), ("shared-owner-entity", 0x60, 8),
            ("custom-key-object", 0x68, 8), ("parameter-name-object", 0x70, 8),
            ("owner-entity", 0x78, 8), ("target-type", 0x80, 4),
            ("parameter-hash", 0x84, 4), ("set-once", 0x88, 1),
        ),
        "methods": {"OnUpdate": 0x14A1F2A0, "OnReset": 0x14A1F830},
        "field_lines": (
            "public SharedBool boolValue; // 0x58",
            "public SharedGameEntity SharedOwnerEntity; // 0x60",
            "public SharedString CustomKey; // 0x68",
            "public SharedString paramaterName; // 0x70",
            "private Entity ownerEntity; // 0x78",
            "public AITargetType TargetType; // 0x80",
            "private int hashID; // 0x84",
            "public bool setOnce; // 0x88",
        ),
    },
}

ODK_METHODS = {
    ".ctor": 0x101B4B90,
    "Start": 0x101B3CF0,
    "Update": 0x101B45F0,
    "OnDestroy": 0x101B3F80,
    "CreateFilters": 0x101B41F0,
}

ODK_FIELDS = (
    ("system-name-object", 0x10, 8), ("filter-not-empty-count", 0x18, 4),
    ("fixed-frame-always-60", 0x1C, 1), ("has-dependency", 0x1D, 1),
    ("entity-int-dictionary", 0x20, 8), ("runtime-state-object", 0x28, 8),
    ("int-list", 0x30, 8), ("unknown-runtime-object", 0x38, 8),
    ("entity-id-set-a", 0x40, 8), ("entity-id-set-b", 0x48, 8),
    ("ecs-filter-object", 0x50, 8), ("job-handle-storage", 0x58, 16),
    ("runtime-flag", 0x68, 1),
)

FILTER_FIELDS = (
    ("filter-system", 0x18, 8), ("filter-debug-name-object", 0x50, 8),
    ("filter-world", 0x78, 8), ("filter-entity-list", 0x98, 8),
    ("filter-index", 0xD0, 4), ("filter-runnable-entity-count", 0xD4, 4),
    ("filter-entity-count", 0x170, 4),
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, str]:
    path = path.resolve()
    return {"path": str(path), "sha256": file_hash(path)}


def _find_sequence(path: Path, expected: tuple[str, ...]) -> tuple[int, int]:
    lines = path.read_text(encoding="utf-8-sig", errors="strict").splitlines()
    wanted = [line.strip() for line in expected]
    for start in range(0, len(lines) - len(wanted) + 1):
        if [line.strip() for line in lines[start:start + len(wanted)]] == wanted:
            return start + 1, start + len(wanted)
    raise ValueError(f"authoritative field sequence not found in {path}: {wanted[0]}")


def _method_records(path: Path, type_ids: set[int]) -> dict[tuple[int, str], int]:
    result: dict[tuple[int, str], int] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        parts = line.split("|")
        if len(parts) >= 5 and parts[0] == "METHOD" and int(parts[1]) in type_ids:
            key = (int(parts[1]), parts[3])
            if key in result:
                raise ValueError(f"duplicate reflected method record: {key}")
            result[key] = int(parts[4], 16)
    return result


def _read(read_id: str, base: str, offset: int, width: int, evidence: list[str]) -> dict[str, Any]:
    op = "block" if width not in (1, 2, 4, 8) else "scalar"
    row: dict[str, Any] = {"id": read_id, "base": base, "offset": offset, "op": op,
                           "phase": "enter", "evidence": evidence}
    row["size" if op == "block" else "width"] = width
    return row


def _instruction_contract(game: NativePE) -> dict[str, Any]:
    row = game.by_start.get(0x7585E30)
    if row is None:
        raise ValueError("job wrapper is not an exact .pdata entry")
    decoded = game.decode(row)
    instructions = {item["rva"]: (item["mnemonic"], item["operands"], item["direct_target_rva"])
                    for item in decoded["instructions"]}
    expected = {
        0x7585E3E: ("mov", "rsi, r9", None),
        0x7585E41: ("mov", "rdi, rcx", None),
        0x7585E44: ("mov", "ebx, dword ptr [rsp + 0x90]", None),
        0x7585EB0: ("mov", "rcx, rdi", None),
        0x7585EB3: ("mov", "edx, ebp", None),
        0x7585EB5: ("call", "0x192df4580", 0x12DF4580),
    }
    for rva, wanted in expected.items():
        if instructions.get(rva) != wanted:
            raise ValueError(f"job wrapper instruction drift at {rva:#x}: {instructions.get(rva)}")
    return {"entry_rva": row.begin, "end_rva": row.end,
            "decoded_instruction_count": len(decoded["instructions"]),
            "all_declared_bytes_decoded": decoded["all_declared_bytes_decoded"],
            "verified_instructions": [f"0x{rva:x}" for rva in expected]}


def _point_method(point_id: str) -> str:
    name = point_id.split("@", 1)[0]
    return name.rsplit(".", 1)[1]


def _bytes(read: dict[str, Any]) -> int:
    return int(read.get("size", read.get("width", 8)))


def run(plan_path: Path, field_dump: Path, task_methods: Path, ecs_methods: Path,
        job_reflection: Path, output: Path) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    plan = _load(plan_path)
    validate(plan, verify_sources=True)
    if plan.get("schema") != "uc.capture-plan.v1" or len(plan.get("points", [])) != 41:
        raise ValueError("expected the source-bound 41-point controller frontier")

    anchors = []
    for type_id, layout in TASK_LAYOUTS.items():
        start, end = _find_sequence(field_dump, layout["field_lines"])
        anchors.append({"source": "runtime-field-layout", "type_id": type_id,
                        "type_name": layout["name"], "line_start": start, "line_end": end})
    odk_start, odk_end = _find_sequence(field_dump, (
        "private Dictionary`2<uint,int> BENFLBICPCO; // 0x20",
        "private PPGHADGLAOL FBABJJEMBAE; // 0x28",
        "private List`1<int> KLJBJAGPPLH; // 0x30",
        "private !gen(0x3c5e8) CPKOEHGMHHG; // 0x38",
        "private HashSet`1<uint> HEKBGDPEBEI; // 0x40",
        "private HashSet`1<uint> HKKENNIFICK; // 0x48",
        "private EcsFilter AKIGKGOMIDM; // 0x50",
        "private JobHandle ILDJGHGAMOO; // 0x58",
        "private bool NIBDJIJEGDJ; // 0x68",
    ))
    anchors.append({"source": "runtime-field-layout", "type_id": 48224,
                    "type_name": "ODKPBBAJAEG", "line_start": odk_start, "line_end": odk_end})
    filter_start, filter_end = _find_sequence(field_dump, (
        "public EcsSystem System; // 0x18",
        "internal !gen(0x26f8c) OnEntityReadyPostActionItem; // 0x20",
        "protected CIKBEEAOAND readyEntitySet; // 0x28",
    ))
    # Additional exact fields are individually required because they are not contiguous.
    for line in (
        "public String DebugName; // 0x50", "protected EcsWorld worldRef; // 0x78",
        "protected !gen(0x2702e) entityList; // 0x98", "internal int FilterIndex; // 0xd0",
        "private int <RunnableEntityCount>k__BackingField; // 0xd4",
        "private int <EntityCount>k__BackingField; // 0x170",
        "internal IntPtr jobGroup; // 0x10", "internal int version; // 0x18",
        "internal int BatchSize; // 0x10", "internal int NumJobs; // 0x14",
        "public int TotalIterationCount; // 0x18", "internal int NumPhases; // 0x1c",
        "internal IntPtr StartEndIndex; // 0x20", "internal IntPtr PhaseData; // 0x28",
    ):
        _find_sequence(field_dump, (line,))
    anchors.append({"source": "runtime-field-layout", "type_name": "EcsFilter",
                    "line_start": filter_start, "line_end": filter_end,
                    "noncontiguous_fields_verified": len(FILTER_FIELDS) - 1})

    task_records = _method_records(task_methods, set(TASK_LAYOUTS))
    for type_id, layout in TASK_LAYOUTS.items():
        for method, rva in layout["methods"].items():
            if task_records.get((type_id, method)) != rva:
                raise ValueError(f"task method reflection mismatch: {type_id} {method}")
    ecs_records = _method_records(ecs_methods, {48224})
    for method, rva in ODK_METHODS.items():
        if ecs_records.get((48224, method)) != rva:
            raise ValueError(f"ECS method reflection mismatch: {method}")
    create_line = next(line for line in ecs_methods.read_text(encoding="utf-8-sig").splitlines()
                       if line.startswith("METHOD|48224|4|CreateFilters|"))
    if "|params=1|" not in create_line or "EcsWorld" not in create_line:
        raise ValueError("CreateFilters EcsWorld parameter is not reflected")

    job_lines = job_reflection.read_text(encoding="utf-8-sig").splitlines()
    required_job = {
        "CLOSED|": "name=IKNHGFBHLLK|token=0x2001f53",
        "METHOD-SLOT|": "class=ParallelForJobStruct`1|name=Execute|code-rva=0x7585e30",
        "METHOD-CLASS-ARG[0]|": "name=IKNHGFBHLLK|token=0x2001f53",
    }
    for prefix, fragment in required_job.items():
        if not any(line.startswith(prefix) and fragment in line for line in job_lines):
            raise ValueError(f"job reflection evidence missing: {prefix} {fragment}")

    derived = copy.deepcopy(plan)
    derived["plan_id"] = plan["plan_id"] + "-field-enriched"
    derived["plan_revision"] = int(plan["plan_revision"]) + 1
    derived["sources"].update({
        "runtime-field-layout": _source(field_dump),
        "task-method-reflection": _source(task_methods),
        "ecs-method-reflection": _source(ecs_methods),
        "job-wrapper-reflection": _source(job_reflection),
        "field-enrichment-tool": _source(Path(__file__)),
    })
    game_path = Path(derived["sources"]["game-module"]["path"])
    job_contract = _instruction_contract(NativePE(game_path))

    task_by_rva = {(rva, method): (type_id, layout)
                   for type_id, layout in TASK_LAYOUTS.items()
                   for method, rva in layout["methods"].items()}
    enriched = []
    total_added = 0
    maximum_point_bytes = 0
    for point in derived["points"]:
        added: list[dict[str, Any]] = []
        task_key = (int(point["rva"]), _point_method(point["id"]))
        if task_key in task_by_rva:
            type_id, layout = task_by_rva[task_key]
            evidence = ["runtime-field-layout", "task-method-reflection"]
            added = [_read(name, "rcx", offset, width, evidence)
                     for name, offset, width in layout["fields"]]
            category = "behavior-task-fields"
            authority = {"type_id": type_id, "method": task_key[1]}
        elif int(point["rva"]) in ODK_METHODS.values():
            evidence = ["runtime-field-layout", "ecs-method-reflection"]
            added = [_read(name, "rcx", offset, width, evidence)
                     for name, offset, width in ODK_FIELDS]
            method = next(name for name, rva in ODK_METHODS.items() if rva == int(point["rva"]))
            if method == "CreateFilters":
                added.append({"id": "ecs-world-argument-raw", "base": "rdx", "op": "register",
                              "width": 8, "phase": "enter", "evidence": evidence})
            if method == "Update":
                added.extend(_read(name, "ecs-filter-object", offset, width, evidence)
                             for name, offset, width in FILTER_FIELDS)
            category = "ecs-system-fields"
            authority = {"type_id": 48224, "method": method}
        elif int(point["rva"]) == 0x7585E30:
            evidence = ["game-module", "runtime-field-layout", "job-wrapper-reflection"]
            added = [
                {"id": reg, "base": reg.removeprefix("raw-"), "op": "register", "width": 8,
                 "phase": "enter", "evidence": evidence}
                for reg in ("raw-rdx", "raw-r8", "raw-r9")
            ]
            added.extend((
                _read("raw-stack-argument-5", "rsp", 0x28, 4, evidence),
                _read("raw-job-ranges-window", "r9", 0, 0x20, evidence),
            ))
            category = "parallel-job-raw-abi"
            authority = {"closed_type": "IKNHGFBHLLK", "wrapper": "ParallelForJobStruct`1.Execute"}
        else:
            continue
        existing = {row["id"] for row in point.get("reads", [])}
        if existing & {row["id"] for row in added}:
            raise ValueError(f"read id collision at {point['id']}")
        point.setdefault("reads", []).extend(added)
        point["field_read_contract"] = {
            "category": category,
            "raw_evidence_only": True,
            "semantic_upgrade": False,
            "authority": authority,
        }
        added_bytes = sum(_bytes(row) for row in added)
        point_bytes = sum(_bytes(row) for row in point["reads"])
        total_added += added_bytes
        maximum_point_bytes = max(maximum_point_bytes, point_bytes)
        enriched.append({"point": point["id"], "category": category,
                         "added_reads": [row["id"] for row in added],
                         "added_bytes": added_bytes, "record_bytes": point_bytes,
                         "authority": authority})

    if len(enriched) != 16:
        raise ValueError(f"expected 16 field/ABI-enriched points, got {len(enriched)}")
    validation = validate(derived, verify_sources=True)
    output.mkdir(parents=True)
    plan_out = output / "capture-plan.field-enriched.json"
    plan_out.write_bytes(canonical(derived))
    report = {
        "schema": "uc.controller-field-read-plan.v1",
        "source_plan": _source(plan_path),
        "output_plan": _source(plan_out),
        "logical_points": len(derived["points"]),
        "enriched_points": len(enriched),
        "task_points": sum(row["category"] == "behavior-task-fields" for row in enriched),
        "ecs_points": sum(row["category"] == "ecs-system-fields" for row in enriched),
        "job_points": sum(row["category"] == "parallel-job-raw-abi" for row in enriched),
        "total_added_read_bytes_per_full_point_set": total_added,
        "maximum_point_record_bytes": maximum_point_bytes,
        "declared_max_record_bytes": int(derived["resources"]["max_record_bytes"]),
        "validation": validation,
        "field_anchors": anchors,
        "job_instruction_contract": job_contract,
        "points": enriched,
        "semantic_limits": [
            "Raw harvested fields do not establish ObjectInstance or EntityIdentity.",
            "SharedVariable<T> payloads are not interpreted without a closed layout for that exact T.",
            "The parallel job registers and stack value remain raw ABI evidence.",
            "EcsFilter nested reads are enabled only on ODKPBBAJAEG.Update.",
        ],
    }
    report_out = output / "report.json"
    report_out.write_bytes(canonical(report))
    print(json.dumps({"report": str(report_out), **{key: report[key] for key in (
        "logical_points", "enriched_points", "task_points", "ecs_points", "job_points",
        "total_added_read_bytes_per_full_point_set", "maximum_point_record_bytes")}},
        ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--field-dump", type=Path, required=True)
    parser.add_argument("--task-methods", type=Path, required=True)
    parser.add_argument("--ecs-methods", type=Path, required=True)
    parser.add_argument("--job-reflection", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    run(args.plan.resolve(), args.field_dump.resolve(), args.task_methods.resolve(),
        args.ecs_methods.resolve(), args.job_reflection.resolve(), args.out.resolve())
