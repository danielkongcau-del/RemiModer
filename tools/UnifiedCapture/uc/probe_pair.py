from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .model import canonical, file_hash, sha, uint
from .native_manifest import validate_exit_manifest


SCHEMA = "uc.capture-plan.v2"
REQUIREMENTS = ("none", "completion", "return_value", "path_identity")


@dataclass(frozen=True)
class LogicalSubscription:
    observation_id: str
    role: str
    function_id: str
    exit_site_id: str | None


@dataclass(frozen=True)
class PhysicalProbeSite:
    module: str
    rva: int
    span: int
    expected_bytes: bytes
    backend_build_hash: str
    patch_contract_hash: str
    subscriptions: tuple[LogicalSubscription, ...]


@dataclass(frozen=True)
class CompiledProbePairPlan:
    plan_id: str
    plan_revision: int
    plan_hash: str
    sites: tuple[PhysicalProbeSite, ...]
    canonical_source: bytes


def _integer_only(value: Any):
    if isinstance(value, float):
        raise ValueError("CapturePlan uses integer bit patterns, not floating JSON numbers")
    if isinstance(value, dict):
        for child in value.values():
            _integer_only(child)
    elif isinstance(value, list):
        for child in value:
            _integer_only(child)


def _prefix(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or len(value) < 2 or len(value) % 2:
        raise ValueError(f"{name}: expected non-empty even-length hex")
    try:
        result = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name}: invalid hex") from error
    if value != value.lower():
        raise ValueError(f"{name}: hex must be lower-case")
    return result


def _patch_contract(value: Any, expected: bytes, name: str) -> tuple[str, int, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{name}: backend patch contract required")
    build_hash = sha(value.get("backend_build_hash"))
    span = uint(value.get("required_redirect_span"), f"{name}.required_redirect_span", 256)
    relocated = uint(value.get("relocated_span"), f"{name}.relocated_span", 256)
    if not span or relocated < span or len(expected) < span:
        raise ValueError(f"{name}: redirect/relocation span is not covered by expected bytes")
    if value.get("redirect_kind") not in ("near", "far"):
        raise ValueError(f"{name}: redirect_kind")
    if value.get("fault_in_relocated_span_test") != "passed-own-fixture":
        raise ValueError(f"{name}: relocated-span fault safety is not qualified")
    if value.get("architectural_rsp_test") != "passed-own-fixture":
        raise ValueError(f"{name}: architectural RSP is not qualified")
    policy = value.get("cet_cfg_test")
    if policy not in ("passed-own-fixture", "target-runtime-required", "target-runtime-observed"):
        raise ValueError(f"{name}: CET/CFG state is not accounted for")
    if policy == "target-runtime-observed":
        identity = value.get("target_process_identity", {})
        target_policy = value.get("target_process_policy", {})
        uint(identity.get("pid"), f"{name}.target_process_identity.pid", (1 << 32) - 1)
        uint(identity.get("creation_time_100ns"), f"{name}.target_process_identity.creation_time_100ns")
        for key in ("cfg_enabled", "cet_user_shadow_stack_enabled", "cet_user_shadow_stack_strict"):
            if not isinstance(target_policy.get(key), bool):
                raise ValueError(f"{name}.{key}: target policy bit required")
    return build_hash, span, hashlib.sha256(canonical(value)).hexdigest()


def _verified_source_prefix(value: Any, name: str) -> bytes:
    result = _prefix(value, name)
    if len(result) < 16:
        raise ValueError(f"{name}: at least 16 file-verified source bytes required")
    return result


def _validate_reads(reads: Any, sources: dict, max_bytes: int, name: str):
    if not isinstance(reads, list):
        raise ValueError(f"{name}: reads must be an array")
    ids: set[str] = set()
    total = 0
    for read in reads:
        rid = read.get("id")
        if not isinstance(rid, str) or not rid or rid in ids:
            raise ValueError(f"{name}: duplicate/empty read id")
        ids.add(rid)
        refs = read.get("evidence", [])
        if not refs or any(ref not in sources for ref in refs):
            raise ValueError(f"{name}: read lacks existing evidence")
        base = read.get("base")
        if base not in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip") \
                and base not in ids:
            raise ValueError(f"{name}: raw probe read base must be a register or earlier scalar")
        op = read.get("op", "scalar")
        if op in ("scalar", "relative"):
            size = uint(read.get("width", 8), f"{name}.width", 8)
            if size not in (1, 2, 4, 8):
                raise ValueError(f"{name}: scalar width")
        elif op == "block":
            size = uint(read.get("size"), f"{name}.size", max_bytes)
        else:
            raise ValueError(f"{name}: v2 probe-pair initially supports scalar/relative/block reads")
        total += size
        if total > max_bytes:
            raise ValueError(f"{name}: read program exceeds max_record_bytes")


def _eligible_candidate(candidate: dict, requirement: str, build_hash: str, name: str):
    if not candidate.get("incoming_edges_complete"):
        raise ValueError(f"{name}: incoming edge coverage is incomplete")
    contract = candidate.get("exit_capture_contract", {})
    if contract.get("probe_semantics") != "pre_instruction":
        raise ValueError(f"{name}: unsupported probe semantics")
    if contract.get("relocation_class") != "pure_epilogue" or contract.get("exception_neutral_relocation") is not True:
        raise ValueError(f"{name}: relocation is not qualified exception-neutral pure epilogue")
    if requirement == "return_value" and not (contract.get("return_value_stable") is True and
                                               contract.get("xmm_return_stable") is True):
        raise ValueError(f"{name}: return channels are not stable")
    patch = candidate.get("backend_patch_contract")
    semantic = _prefix(candidate.get("expected_bytes"), f"{name}.expected_bytes")
    expected = _verified_source_prefix(candidate.get("verified_source_prefix"),
                                       f"{name}.verified_source_prefix")
    if not expected.startswith(semantic):
        raise ValueError(f"{name}: semantic exit bytes differ from verified source prefix")
    candidate_hash, span, patch_hash = _patch_contract(patch, expected, name)
    if candidate_hash != build_hash:
        raise ValueError(f"{name}: backend build differs from entry site")
    if patch.get("probe_rva") not in (None, candidate.get("probe_rva")):
        raise ValueError(f"{name}: patch contract RVA mismatch")
    return expected, span, patch_hash


def compile_probe_pair(plan: dict, *, verify_sources: bool = True) -> CompiledProbePairPlan:
    """Compile v2 without installing hooks; failures are publication blockers."""
    _integer_only(plan)
    if plan.get("schema") != SCHEMA:
        raise ValueError("unsupported probe-pair plan schema")
    if plan.get("activation_status") == "BLOCKED_PENDING_TARGET_QUALIFICATION":
        raise ValueError("plan is blocked pending target-process site qualification")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not plan_id:
        raise ValueError("plan_id required")
    revision = uint(plan.get("plan_revision"), "plan_revision")
    modules = plan.get("modules", {})
    if not modules:
        raise ValueError("modules required")
    for alias, module in modules.items():
        if not alias or not module.get("image"):
            raise ValueError("module alias/image required")
        sha(module.get("sha256"))
    sources = plan.get("sources", {})
    if not sources:
        raise ValueError("sources required")
    for source in sources.values():
        sha(source.get("sha256"))
        if verify_sources and file_hash(Path(source["path"])) != source["sha256"]:
            raise ValueError(f"source changed: {source['path']}")
    resources = plan.get("resources", {})
    max_bytes = uint(resources.get("max_record_bytes"), "max_record_bytes", (1 << 32) - 1)
    for key in ("event_slots_per_observation", "call_frames_per_function", "thread_nesting_limit"):
        if uint(resources.get(key), key, (1 << 32) - 1) == 0:
            raise ValueError(f"{key}: zero not supported")
    policy = plan.get("physical_site_policy", {})
    if policy.get("exact_site_sharing") != "share-one-listener-multiple-logical-subscriptions" or \
            policy.get("partial_overlap") != "reject":
        raise ValueError("physical site ownership policy")

    site_rows: list[dict] = []
    observation_ids: set[str] = set()
    for observation in plan.get("observations", []):
        oid = observation.get("id")
        if not isinstance(oid, str) or not oid or oid in observation_ids:
            raise ValueError("duplicate/empty observation id")
        observation_ids.add(oid)
        if observation.get("backend") != "gum_function_probe_pair":
            raise ValueError(f"{oid}: unsupported backend")
        module = observation.get("module")
        if module not in modules:
            raise ValueError(f"{oid}: unknown module")
        refs = observation.get("evidence", [])
        if not refs or any(ref not in sources for ref in refs):
            raise ValueError(f"{oid}: observation lacks existing evidence")
        requirement = observation.get("exit_capture_requirement")
        if requirement not in REQUIREMENTS:
            raise ValueError(f"{oid}: exit_capture_requirement")

        entry = observation.get("entry", {})
        entry_rva = uint(entry.get("rva"), f"{oid}.entry.rva")
        entry_expected = _verified_source_prefix(entry.get("expected_prefix"), f"{oid}.entry.expected_prefix")
        build_hash, entry_span, entry_patch_hash = _patch_contract(
            entry.get("backend_patch_contract"), entry_expected, f"{oid}.entry")
        _validate_reads(entry.get("reads", []), sources, max_bytes, f"{oid}.entry")
        site_rows.append({"module": module, "rva": entry_rva, "span": entry_span,
                          "expected": entry_expected, "build": build_hash,
                          "patch": entry_patch_hash,
                          "subscription": LogicalSubscription(oid, "entry", "", None)})

        manifest_ref = observation.get("native_exit_manifest", {})
        manifest_path = Path(manifest_ref.get("path", ""))
        if file_hash(manifest_path) != sha(manifest_ref.get("sha256")):
            raise ValueError(f"{oid}: native exit manifest changed")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        validate_exit_manifest(manifest)
        function_id = manifest_ref.get("function_id")
        matches = [row for row in manifest["functions"] if row.get("function_id") == function_id]
        if len(matches) != 1:
            raise ValueError(f"{oid}: function_id not unique in native exit manifest")
        function = matches[0]
        if function.get("module") != module or function.get("entry_rva") != entry_rva:
            raise ValueError(f"{oid}: entry does not match native exit manifest")
        site_rows[-1]["subscription"] = LogicalSubscription(oid, "entry", function_id, None)
        if requirement == "none":
            continue
        complete = function.get("completeness", {})
        if complete.get("normal_exit_set_complete") is not True or complete.get("cold_fragments_complete") is not True:
            raise ValueError(f"{oid}: normal exit/cold fragment coverage is incomplete")
        exits = function.get("normal_exits", [])
        if not exits:
            raise ValueError(f"{oid}: no verified normal exits")
        for exit_site in exits:
            sid = exit_site.get("exit_site_id")
            if exit_site.get("terminal_semantics") != "normal_return" or exit_site.get("terminal_semantics_verified") is not True:
                raise ValueError(f"{oid}/{sid}: terminal semantics are not verified")
            candidates = []
            failures = []
            for candidate in exit_site.get("probe_candidates", []):
                try:
                    expected, span, patch_hash = _eligible_candidate(candidate, requirement, build_hash, f"{oid}/{sid}")
                    candidates.append((candidate, expected, span, patch_hash))
                except ValueError as error:
                    failures.append(str(error))
            if not candidates:
                raise ValueError(f"{oid}/{sid}: no activation-safe candidate: {'; '.join(failures)}")
            candidates.sort(key=lambda row: (row[2], row[0]["probe_rva"]))
            candidate, expected, span, patch_hash = candidates[0]
            site_rows.append({"module": module, "rva": candidate["probe_rva"], "span": span,
                              "expected": expected, "build": build_hash, "patch": patch_hash,
                              "subscription": LogicalSubscription(oid, "normal_exit", function_id, sid)})
    if not observation_ids:
        raise ValueError("observations required")

    grouped: dict[tuple, list[LogicalSubscription]] = {}
    ranges: list[tuple[str, int, int, tuple]] = []
    for row in site_rows:
        key = (row["module"], row["rva"], row["span"], row["expected"], row["build"], row["patch"])
        for old_module, old_begin, old_end, old_key in ranges:
            if old_module != row["module"] or old_end <= row["rva"] or row["rva"] + row["span"] <= old_begin:
                continue
            if old_key != key:
                raise ValueError("partial/mismatched physical probe site overlap")
        if key not in grouped:
            ranges.append((row["module"], row["rva"], row["rva"] + row["span"], key))
            grouped[key] = []
        grouped[key].append(row["subscription"])
    sites = tuple(PhysicalProbeSite(module, rva, span, expected, build, patch, tuple(subscriptions))
                  for (module, rva, span, expected, build, patch), subscriptions in
                  sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])))
    return CompiledProbePairPlan(plan_id, revision, hashlib.sha256(canonical(plan)).hexdigest(),
                                 sites, canonical(plan))
