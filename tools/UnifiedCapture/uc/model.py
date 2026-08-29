from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

SCHEMA = "uc.capture-plan.v1"
REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
             "r10", "r11", "r12", "r13", "r14", "r15", "rip")
LEGACY_ABIS = ("void_p", "void_pp", "state_ptr", "state_id", "float_name", "float_id",
               "bool_name", "bool_id", "int_name", "int_id", "trigger_name", "trigger_id",
               "damp_name", "damp_id")

def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")

def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def uint(value, name, maximum=(1 << 64) - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name}: expected unsigned integer <= {maximum}")
    return value

def sha(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("SHA-256 must be 64 lower-case hex digits")
    return value

def validate(plan: dict, *, verify_sources=False) -> dict:
    def integer_only(value):
        if isinstance(value, float):
            raise ValueError("CapturePlan uses integer bit patterns, not floating JSON numbers")
        if isinstance(value, dict):
            for child in value.values():
                integer_only(child)
        elif isinstance(value, list):
            for child in value:
                integer_only(child)
    integer_only(plan)
    if plan.get("schema") != SCHEMA:
        raise ValueError("unsupported plan schema")
    if not isinstance(plan.get("plan_id"), str) or not plan["plan_id"]:
        raise ValueError("plan_id required")
    uint(plan["plan_revision"], "plan_revision")
    modules = plan.get("modules", {})
    if not modules:
        raise ValueError("modules required")
    for alias, module in modules.items():
        if not alias or not module.get("image"):
            raise ValueError("module alias/image required")
        sha(module["sha256"])
    resources = plan.get("resources", {})
    for key in ("slots_per_point", "max_record_bytes"):
        if uint(resources.get(key), key, (1 << 32) - 1) == 0:
            raise ValueError(f"{key}: zero not supported")
    sources = plan.get("sources", {})
    for source in sources.values():
        sha(source["sha256"])
        if verify_sources and file_hash(Path(source["path"])) != source["sha256"]:
            raise ValueError(f"source changed: {source['path']}")
    ids = set()
    points = plan.get("points", [])
    if not points:
        raise ValueError("points required")
    for point in points:
        name = point["id"]
        if not isinstance(name, str) or not name or name in ids:
            raise ValueError("duplicate/empty point id")
        ids.add(name)
        backend = point["backend"]
        if backend not in ("slot", "gum_probe"):
            raise ValueError("unsupported observation backend")
        if point["module"] not in modules:
            raise ValueError("unknown point module")
        uint(point["rva"], "rva")
        evidence = point.get("evidence", [])
        if not evidence or any(item not in sources for item in evidence):
            raise ValueError("every point needs existing evidence references")
        if backend == "slot":
            if point.get("abi") not in LEGACY_ABIS:
                raise ValueError("slot requires a supported verified ABI")
            if point.get("target_module") not in modules:
                raise ValueError("slot target_module required")
            if point.get("target_resolution") != "live-slot":
                uint(point["target_rva"], "target_rva")
        prefix = point.get("expected_prefix", "")
        if "expected_prefix_from_module_file" in point:
            if backend != "slot" or not 16 <= uint(point["expected_prefix_from_module_file"], "prefix length", 256):
                raise ValueError("module file prefix requires slot and 16..256 bytes")
        else:
            if not isinstance(prefix, str) or len(prefix) < 2 or len(prefix) % 2:
                raise ValueError("expected instruction prefix required")
            bytes.fromhex(prefix)
        if "legacy_reader" in point:
            reader = point["legacy_reader"]
            if backend != "slot" or reader.get("id") not in ("consumer-p1au-v1", "state-step-p1bo-v1"):
                raise ValueError("unsupported frozen reader/backend")
            sha(reader["source_digest"])
            if reader.get("module") not in modules or not reader.get("evidence") or any(r not in sources for r in reader["evidence"]):
                raise ValueError("frozen reader requires module and evidence")
            kind = uint(reader["kind"], "frozen reader kind", 9)
            if reader["id"] == "state-step-p1bo-v1":
                if kind > 2:
                    raise ValueError("state step kind")
                uint(reader["expected_vtable_rva"], "vtable")
            elif kind not in (1, 3, 5, 7, 9):
                raise ValueError("consumer kind")
        available = {}
        total = 0
        for read in point.get("reads", []):
            rid = read["id"]
            if not isinstance(rid, str) or not rid or rid in available:
                raise ValueError("duplicate/empty read id")
            base = read["base"]
            if backend == "slot" and base in REGISTERS:
                raise ValueError("legacy backend does not provide raw CPU registers")
            if base not in available and base not in REGISTERS and base not in tuple(f"arg{i}" for i in range(8)):
                if not base.startswith("module:") or base[7:] not in modules:
                    raise ValueError("read base must be register, ABI arg, module or earlier read")
            if backend == "gum_probe" and base.startswith("arg"):
                raise ValueError("instruction probe has no function arguments")
            if base.startswith("arg") and not point.get("abi"):
                raise ValueError("semantic arg requires an explicitly verified ABI")
            if base.startswith("arg") and backend != "slot":
                raise ValueError("this backend does not expose verified semantic arguments")
            uint(read.get("offset", 0), "read offset")
            phase = read.get("phase", "both")
            if phase not in ("enter", "leave", "both") or (backend == "gum_probe" and phase != "enter"):
                raise ValueError("invalid read phase")
            op = read.get("op", "scalar")
            if op in ("scalar", "relative"):
                size = read.get("width", 8)
                if size not in (1, 2, 4, 8):
                    raise ValueError("scalar width")
            elif op == "block":
                size = uint(read["size"], "block size", (1 << 32) - 1)
                if not size:
                    raise ValueError("block size must be nonzero")
            elif op == "string":
                size = uint(read["max_bytes"], "string capacity", 4096)
                if not size:
                    raise ValueError("string capacity")
            elif op == "array":
                if read["count_from"] not in available:
                    raise ValueError("array count must refer to earlier read")
                stride = uint(read["stride"], "stride")
                max_count = uint(read["max_count"], "max_count")
                if not stride or not max_count:
                    raise ValueError("zero array stride/count bound")
                size = stride * max_count
            else:
                raise ValueError("unknown read operation")
            when = read.get("when")
            if when is not None:
                if not isinstance(when, dict) or when.get("op") not in ("eq", "neq"):
                    raise ValueError("predicate op must be eq/neq")
                uint(when.get("value"), "predicate value")
                if "mask" in when:
                    uint(when["mask"], "predicate mask")
                if op not in ("scalar", "relative") or phase != "enter":
                    raise ValueError("predicate requires an enter-phase scalar/relative read")
            if not read.get("evidence") or any(item not in sources for item in read["evidence"]):
                raise ValueError("read operation lacks evidence")
            for dependency in ([base] if base in available else []) + ([read["count_from"]] if op == "array" else []):
                prior = available[dependency]
                if prior.get("op", "scalar") not in ("scalar", "relative"):
                    raise ValueError("read dependency is not a scalar")
                phases = {"enter": {1}, "leave": {2}, "both": {1, 2}}
                if not phases[phase] <= phases[prior.get("phase", "both")]:
                    raise ValueError("read dependency unavailable at selected phase")
            total += size
            available[rid] = read
        retention = point.get("retention")
        if retention is not None:
            if backend != "gum_probe" or not isinstance(retention, dict) or \
                    retention.get("mode") != "first_per_entry_return_address":
                raise ValueError("return-address retention requires an entry-only instruction probe")
            capacity = uint(retention.get("max_keys"), "retention max_keys", 65536)
            if not capacity or capacity & (capacity - 1):
                raise ValueError("retention max_keys must be a nonzero power of two")
            if any("when" in read for read in point.get("reads", [])):
                raise ValueError("return-address retention cannot be combined with read predicates")
        if total > resources["max_record_bytes"]:
            raise ValueError("read program exceeds declared record byte budget")
    return {"plan_hash": digest(plan), "points": len(points), "source_count": len(sources),
            "automatic_stop": False, "semantic_validation": "evidence-references-not-proof-of-layout"}

@dataclass(frozen=True)
class CompiledPlan:
    plan_id: str
    plan_revision: int
    plan_hash: str
    generation: int
    session_id: str
    bindings: tuple
    # Immutable portable compile result; native compiler additionally emits ReadOps.
    canonical_source: bytes

def resolve(plan, actual_modules, generation, session_id):
    result = validate(plan)
    bindings = []
    for alias, wanted in plan["modules"].items():
        if alias not in actual_modules:
            raise LookupError(f"WAITING_MODULE:{alias}")
        actual = actual_modules[alias]
        if actual["sha256"] != wanted["sha256"]:
            raise ValueError(f"module version mismatch:{alias}")
        if not actual.get("load_identity"):
            raise ValueError("module load identity required")
    for point in plan["points"]:
        module = actual_modules[point["module"]]
        if point["rva"] >= module["size"]:
            raise ValueError("RVA outside module")
        bindings.append((point["id"], module["base"] + point["rva"], module["load_identity"]))
    return CompiledPlan(plan["plan_id"], plan["plan_revision"], result["plan_hash"], generation,
                        session_id, tuple(bindings), canonical(plan))
