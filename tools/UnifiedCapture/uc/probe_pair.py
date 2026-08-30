from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from .model import REGISTERS, canonical, file_hash, sha, uint
from .native_manifest import NativePE, validate_exit_manifest


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
    redirect = value.get("redirect_kind")
    if (redirect, span) not in (("near", 5), ("far", 16)) or relocated < span or len(expected) < relocated:
        raise ValueError(f"{name}: redirect/relocation span is not covered by expected bytes")
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


def _validate_reads(reads: Any, sources: dict, modules: dict, max_bytes: int, name: str):
    if not isinstance(reads, list):
        raise ValueError(f"{name}: reads must be an array")
    ids: dict[str, tuple[str, str]] = {}
    totals = {"enter": 0, "leave": 0}
    for read in reads:
        phase = read.get("phase", "enter")
        if phase not in ("enter", "leave"):
            raise ValueError(f"{name}: v2 reads must use enter/leave phase")
        rid = read.get("id")
        if not isinstance(rid, str) or not rid or rid in ids:
            raise ValueError(f"{name}: duplicate/empty read id")
        refs = read.get("evidence", [])
        if not refs or any(ref not in sources for ref in refs):
            raise ValueError(f"{name}: read lacks existing evidence")
        base = read.get("base")
        registers = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")
        entry_register = isinstance(base, str) and base.startswith("entry:") and base[6:] in registers
        module_base = isinstance(base, str) and base.startswith("module:") and base[7:] in modules
        if base not in registers and base not in ids and not entry_register and not module_base:
            raise ValueError(f"{name}: raw probe read base must be a current/entry register, module or earlier scalar")
        if entry_register and phase != "leave":
            raise ValueError(f"{name}: entry register base is leave-phase only")
        if base in ids:
            if ids[base][0] not in ("scalar", "relative", "register"):
                raise ValueError(f"{name}: read dependency must be scalar/relative/register")
            if ids[base][1] != phase:
                raise ValueError(f"{name}: read dependency unavailable at selected phase")
        uint(read.get("offset", 0), f"{name}.offset")
        op = read.get("op", "scalar")
        if op in ("scalar", "relative", "register"):
            size = uint(read.get("width", 8), f"{name}.width", 8)
            if size not in (1, 2, 4, 8):
                raise ValueError(f"{name}: scalar width")
            if op == "register" and ((base not in registers and not entry_register) or read.get("offset", 0) != 0):
                raise ValueError(f"{name}: register read requires a current/entry register base and zero offset")
        elif op == "block":
            size = uint(read.get("size"), f"{name}.size", max_bytes)
            if not size:
                raise ValueError(f"{name}: block size must be nonzero")
        elif op == "string":
            size = uint(read.get("max_bytes"), f"{name}.max_bytes", 4096)
            if not size:
                raise ValueError(f"{name}: string capacity")
        elif op == "array":
            if read.get("count_from") not in ids:
                raise ValueError(f"{name}: array count must refer to an earlier read")
            if ids[read["count_from"]][0] not in ("scalar", "relative", "register"):
                raise ValueError(f"{name}: array count dependency must be scalar/relative/register")
            if ids[read["count_from"]][1] != phase:
                raise ValueError(f"{name}: array count dependency unavailable at selected phase")
            stride = uint(read.get("stride"), f"{name}.stride")
            max_count = uint(read.get("max_count"), f"{name}.max_count")
            if not stride or not max_count:
                raise ValueError(f"{name}: zero array stride/count bound")
            size = stride * max_count
        else:
            raise ValueError(f"{name}: v2 probe-pair supports scalar/relative/register/block/string/array reads")
        when = read.get("when")
        if when is not None:
            if not isinstance(when, dict) or when.get("op") not in ("eq", "neq", "in"):
                raise ValueError(f"{name}: predicate op must be eq/neq/in")
            if when.get("op") == "in":
                values = when.get("values")
                if not isinstance(values, list) or not 1 <= len(values) <= 16 or len(set(values)) != len(values):
                    raise ValueError(f"{name}: predicate in requires 1..16 unique values")
                for value in values:
                    uint(value, f"{name}.predicate.values")
            else:
                uint(when.get("value"), f"{name}.predicate.value")
            if "mask" in when:
                uint(when["mask"], f"{name}.predicate.mask")
            if op not in ("scalar", "relative", "register") or phase != "enter":
                raise ValueError(f"{name}: predicate requires an enter-phase scalar/relative/register read")
        totals[phase] += size
        if totals[phase] > max_bytes:
            raise ValueError(f"{name}: read program exceeds per-phase max_record_bytes")
        # Register only after validation: a read may never reference itself.
        ids[rid] = (op, phase)
    return {phase for phase, total in totals.items() if total}


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


def _module_images(modules: dict, sources: dict) -> dict[str, NativePE]:
    """Resolve immutable module files only when continuation proof needs them."""
    result: dict[str, NativePE] = {}
    for alias, module in modules.items():
        matches = [Path(source["path"]) for source in sources.values()
                   if source.get("sha256") == module.get("sha256")]
        if len(matches) != 1:
            raise ValueError(f"{alias}: caller continuation needs one source with the module hash")
        result[alias] = NativePE(matches[0])
    return result


def _verify_caller_continuations(plan: dict, modules: dict, sources: dict) -> dict[tuple[str, str], list[dict]]:
    """Mechanically verify caller-return sites before any plan is published.

    This proves a bounded statement only: an observed callee entry return
    address has a unique predecessor call, and the selected continuation owns
    a relocatable instruction window with no decoded direct edge into its
    interior.  It is not a complete callee exit proof.
    """
    observations = [row for row in plan.get("observations", []) if row.get("completion") is not None]
    if not observations:
        return {}
    images = _module_images(modules, sources)
    all_interiors: dict[str, set[int]] = {alias: set() for alias in images}
    rows: dict[tuple[str, str], list[dict]] = {}
    for observation in observations:
        oid = observation.get("id", "<unknown>")
        completion = observation.get("completion")
        if not isinstance(completion, dict) or completion.get("mode") != "caller_continuation":
            raise ValueError(f"{oid}: unsupported completion mode")
        sites = completion.get("sites")
        if not isinstance(sites, list) or not sites or len(sites) > 256:
            raise ValueError(f"{oid}: caller continuation sites must contain 1..256 rows")
        seen: set[tuple[str, int]] = set()
        verified = []
        for site in sites:
            name = f"{oid}/{site.get('id', '<unknown>')}"
            if not isinstance(site, dict) or not isinstance(site.get("id"), str) or not site["id"]:
                raise ValueError(f"{oid}: caller continuation site id")
            module = site.get("module")
            if module not in modules:
                raise ValueError(f"{name}: unknown caller module")
            refs = site.get("evidence", [])
            if not refs or any(ref not in sources for ref in refs):
                raise ValueError(f"{name}: continuation lacks existing evidence")
            return_rva = uint(site.get("return_rva"), f"{name}.return_rva")
            identity = (module, return_rva)
            if identity in seen:
                raise ValueError(f"{oid}: duplicate caller continuation")
            seen.add(identity)
            image = images[module]
            if return_rva >= image.size_of_image:
                raise ValueError(f"{name}: caller continuation outside module")
            expected = _verified_source_prefix(site.get("expected_prefix"), f"{name}.expected_prefix")
            if image.bytes_at(return_rva, len(expected)) != expected:
                raise ValueError(f"{name}: continuation source prefix mismatch")
            build_hash, span, patch_hash = _patch_contract(
                site.get("backend_patch_contract"), expected, name)
            patch = site["backend_patch_contract"]
            if patch.get("probe_rva") not in (None, return_rva):
                raise ValueError(f"{name}: patch contract RVA mismatch")
            source_contract = site.get("source_contract", {})
            semantic_span = uint(source_contract.get("semantic_safe_span"),
                                 f"{name}.source_contract.semantic_safe_span", len(expected))
            if semantic_span < 16 or semantic_span > len(expected):
                raise ValueError(f"{name}: continuation semantic safe span")
            if source_contract.get("instruction_boundary_verified_by") != "capstone" or \
                    source_contract.get("predecessor_call_ends_at_return_rva") is not True or \
                    source_contract.get("relocation_window_instruction_complete") is not True or \
                    source_contract.get("direct_interior_edge_free") is not True:
                raise ValueError(f"{name}: incomplete continuation source contract")
            owner = image.containing(return_rva - 1) if return_rva else None
            if owner is None:
                raise ValueError(f"{name}: no pdata owner for predecessor call")
            instructions = image.decode(owner)["instructions"]
            predecessors = [ins for ins in instructions if ins["rva"] + ins["size"] == return_rva]
            if len(predecessors) != 1 or predecessors[0]["mnemonic"] != "call" or \
                    "call" not in predecessors[0].get("groups", []):
                raise ValueError(f"{name}: unique predecessor call not mechanically verified")
            predecessor = predecessors[0]
            declared = site.get("predecessor_call", {})
            expected_predecessor = {
                "callsite_rva": predecessor["rva"], "instruction_size": predecessor["size"],
                "instruction_bytes": predecessor["bytes"],
                "call_kind": "direct" if predecessor.get("direct_target_rva") is not None else "indirect",
            }
            if any(declared.get(key) != value for key, value in expected_predecessor.items()):
                raise ValueError(f"{name}: predecessor call declaration differs from module bytes")
            by_rva = {ins["rva"]: ins for ins in instructions}
            cursor = return_rva
            while cursor < return_rva + semantic_span:
                instruction = by_rva.get(cursor)
                if instruction is None:
                    raise ValueError(f"{name}: continuation safe span is not whole instructions")
                cursor += instruction["size"]
            if cursor != return_rva + semantic_span:
                raise ValueError(f"{name}: continuation safe span ends inside an instruction")
            all_interiors[module].update(range(return_rva + 1, return_rva + semantic_span))
            contract = site.get("capture_contract", {})
            required = {
                "probe_semantics": "pre_instruction",
                "completion_semantics": "normal_return_to_observed_callsite_continuation",
                "same_thread_pairing": True,
                "exceptional_exit_observed": False,
                "return_value_stable": True,
                "xmm_return_stable": True,
            }
            if any(contract.get(key) != value for key, value in required.items()):
                raise ValueError(f"{name}: caller continuation capture contract")
            verified.append({"site": site, "expected": expected, "span": span,
                             "build": build_hash, "patch": patch_hash})
        rows[(oid, "caller_continuation")] = verified
    for module, targets in all_interiors.items():
        if not targets:
            continue
        edges = images[module].direct_control_xrefs(targets)
        if edges:
            first = edges[0]
            raise ValueError(f"caller continuation direct interior edge: {module}+{first['target_rva']:#x}")
    return rows


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
    continuation_rows = _verify_caller_continuations(plan, modules, sources)
    resources = plan.get("resources", {})
    max_bytes = uint(resources.get("max_record_bytes"), "max_record_bytes", (1 << 32) - 1)
    if not max_bytes:
        raise ValueError("max_record_bytes: zero not supported")
    for key in ("event_slots_per_observation", "call_frames_per_function", "thread_nesting_limit"):
        if uint(resources.get(key), key, (1 << 32) - 1) == 0:
            raise ValueError(f"{key}: zero not supported")
    for key in ("call_frames_per_function", "thread_nesting_limit"):
        if resources[key] > 256:
            raise ValueError(f"{key}: native maximum is 256")
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

        retention = observation.get("retention")
        if retention is not None:
            mode = retention.get("mode") if isinstance(retention, dict) else None
            if mode not in ("first_per_entry_return_address", "first_per_composite_key"):
                raise ValueError(f"{oid}: unsupported retention mode")
            capacity = uint(retention.get("max_keys"), f"{oid}.retention.max_keys", 65536)
            if not capacity or capacity & (capacity - 1):
                raise ValueError(f"{oid}: retention max_keys must be a nonzero power of two")
            key = retention.get("key")
            if mode == "first_per_entry_return_address":
                if key is not None:
                    raise ValueError(f"{oid}: legacy return-address retention cannot declare a composite key")
            else:
                if not isinstance(key, list) or not 2 <= len(key) <= 4:
                    raise ValueError(f"{oid}: composite retention key must contain 2..4 raw parts")
                identities = set()
                for index, part in enumerate(key):
                    if not isinstance(part, dict) or part.get("kind") not in (
                            "entry_return_address", "register"):
                        raise ValueError(f"{oid}: composite retention key part")
                    if index == 0 and part["kind"] != "entry_return_address":
                        raise ValueError(f"{oid}: composite retention key must begin with entry_return_address")
                    register = part.get("register") if part["kind"] == "register" else None
                    if part["kind"] == "register" and register not in REGISTERS:
                        raise ValueError(f"{oid}: composite retention key register")
                    identity = (part["kind"], register)
                    if identity in identities:
                        raise ValueError(f"{oid}: duplicate composite retention key part")
                    identities.add(identity)
                    if "mask" in part:
                        uint(part["mask"], f"{oid}.retention.key.mask")
                    refs = part.get("evidence", [])
                    if not refs or any(ref not in sources for ref in refs):
                        raise ValueError(f"{oid}: composite retention key lacks existing evidence")
            callers = retention.get("exact_callers", [])
            if not isinstance(callers, list) or len(callers) > 256:
                raise ValueError(f"{oid}: retention exact_callers must contain at most 256 rows")
            identities = set()
            for caller in callers:
                if not isinstance(caller, dict) or caller.get("module") not in modules:
                    raise ValueError(f"{oid}: exact caller module")
                identity = (caller["module"], uint(caller.get("return_rva"),
                                                    f"{oid}.retention.exact_callers.return_rva"))
                if identity in identities:
                    raise ValueError(f"{oid}: duplicate exact caller")
                identities.add(identity)
                refs = caller.get("evidence", [])
                if not refs or any(ref not in sources for ref in refs):
                    raise ValueError(f"{oid}: exact caller lacks existing evidence")
            if requirement != "none" and not callers:
                raise ValueError(f"{oid}: probe-pair retention requires an exact caller gate")

        entry = observation.get("entry", {})
        entry_rva = uint(entry.get("rva"), f"{oid}.entry.rva")
        entry_expected = _verified_source_prefix(entry.get("expected_prefix"), f"{oid}.entry.expected_prefix")
        build_hash, entry_span, entry_patch_hash = _patch_contract(
            entry.get("backend_patch_contract"), entry_expected, f"{oid}.entry")
        read_phases = _validate_reads(entry.get("reads", []), sources, modules, max_bytes, f"{oid}.entry")
        if retention is not None and any("when" in read for read in entry.get("reads", [])):
            raise ValueError(f"{oid}: return-address retention cannot be combined with read predicates")
        if requirement == "none" and "leave" in read_phases:
            raise ValueError(f"{oid}: leave read requires an exit capture requirement")
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
        completion = observation.get("completion")
        if requirement == "none":
            if completion is not None:
                raise ValueError(f"{oid}: entry-only observation cannot declare completion sites")
            continue
        if completion is not None:
            callers = {(row["module"], int(row["return_rva"]))
                       for row in (retention or {}).get("exact_callers", [])}
            sites = {(row["site"]["module"], int(row["site"]["return_rva"]))
                     for row in continuation_rows[(oid, "caller_continuation")]}
            if callers != sites:
                raise ValueError(f"{oid}: exact caller gates and continuation sites must match exactly")
            for row in continuation_rows[(oid, "caller_continuation")]:
                site = row["site"]
                site_rows.append({"module": site["module"], "rva": site["return_rva"],
                                  "span": row["span"], "expected": row["expected"],
                                  "build": row["build"], "patch": row["patch"],
                                  "subscription": LogicalSubscription(
                                      oid, "caller_continuation", function_id, site["id"])})
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
    # Sort reservations once and check neighbours instead of an O(n^2) scan.
    # Gum reserves a 16-byte physical window even when the selected redirect
    # happens to be the 5-byte near form. Ownership overlap must use that
    # backend reservation, not only the bytes changed in this process run.
    ordered = sorted({(row["module"], row["rva"], row["rva"] + 16,
                       (row["module"], row["rva"], row["span"], row["expected"], row["build"], row["patch"]))
                      for row in site_rows})
    for index, (module, begin, end, key) in enumerate(ordered[:-1]):
        next_module, next_begin, _, next_key = ordered[index + 1]
        if next_module == module and next_begin < end and next_key != key:
            raise ValueError("partial/mismatched physical probe site overlap")
    for row in site_rows:
        key = (row["module"], row["rva"], row["span"], row["expected"], row["build"], row["patch"])
        grouped.setdefault(key, []).append(row["subscription"])
    sites = tuple(PhysicalProbeSite(module, rva, span, expected, build, patch, tuple(subscriptions))
                  for (module, rva, span, expected, build, patch), subscriptions in
                  sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])))
    return CompiledProbePairPlan(plan_id, revision, hashlib.sha256(canonical(plan)).hexdigest(),
                                 sites, canonical(plan))
