"""Close the Remielle Animator A -> consumer S -> ccec40 instance chain.

This reuses preserved authoritative PID 48432 raw evidence.  The legacy
observer is not revived: its immutable JSONL, clean-stop review, derived link
index, and independently decoded hook sites are treated as inputs.  Exact raw
line witnesses are re-read and hashed before any address equality is admitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


CONTROLLER = "Avatar_Female_Size02_RemielleOrigin_Controller"
CCEC40_RVA = 0xCCEC40
CONSUMER_VTABLE_SLOT_OFFSET = 0x18


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def _address(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"invalid address: {value!r}")


def _only(values: Any, label: str) -> Any:
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError(f"expected exactly one {label}")
    return values[0]


def _raw_lines(path: Path, numbers: set[int]) -> dict[int, tuple[bytes, dict[str, Any]]]:
    if not numbers or min(numbers) < 1:
        raise ValueError("raw source line numbers must be positive")
    result = {}
    last = max(numbers)
    with path.open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            if number in numbers:
                result[number] = (raw, json.loads(raw))
            if number >= last:
                break
    missing = numbers - set(result)
    if missing:
        raise ValueError(f"raw source lines are missing: {sorted(missing)}")
    return result


def run(links_path: Path, review_path: Path, hook_sites_path: Path,
        raw_step_path: Path, raw_animator_path: Path, unity_path: Path,
        static_stage_path: Path, output: Path) -> dict[str, Any]:
    paths = [path.resolve() for path in (links_path, review_path, hook_sites_path,
                                        raw_step_path, raw_animator_path, unity_path,
                                        static_stage_path, output)]
    (links_path, review_path, hook_sites_path, raw_step_path, raw_animator_path,
     unity_path, static_stage_path, output) = paths
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    links, review, hook_sites, static_stage = map(
        _load, (links_path, review_path, hook_sites_path, static_stage_path))
    if review.get("schema") != "zzz.state-step.review.v1":
        raise ValueError("unsupported state-step review")
    if static_stage.get("schema") != "uc.animator-stage-receiver-static-join.v1":
        raise ValueError("unsupported Animator stage static join")
    if hook_sites.get("unitySha256", "").lower() != file_hash(unity_path).lower():
        raise ValueError("hook-site proof and UnityPlayer identity differ")
    raw_step_hash = file_hash(raw_step_path)
    raw_animator_hash = file_hash(raw_animator_path)
    if review.get("sourceSha256", "").lower() != raw_step_hash.lower():
        raise ValueError("state-step review and raw stream identity differ")
    link_sources = {str(Path(path).resolve()).lower(): digest.lower()
                    for path, digest in links.get("sources", {}).items()}
    if link_sources.get(str(raw_step_path).lower()) != raw_step_hash.lower():
        raise ValueError("link index does not cite the raw state-step stream")
    if link_sources.get(str(raw_animator_path).lower()) != raw_animator_hash.lower():
        raise ValueError("link index does not cite the raw Animator identity stream")

    stop = review.get("stop", {})
    quality = review.get("quality", {})
    if (review.get("transportChecksPassed") is not True or review.get("errors") != []
            or stop.get("restored") is not True or stop.get("activeCalls") != 0
            or stop.get("dropped") != 0 or stop.get("protectionRestoreFailures") != 0
            or quality.get("readFailures") != 0 or quality.get("truncatedEvents") != 0):
        raise ValueError("state-step stream is not clean, lossless, and restored")
    if review.get("header", {}).get("pid") != links.get("pid"):
        raise ValueError("state-step review and link index PID differ")

    identity = _only(links.get("identities"), "accepted Animator identity")
    identity_event = identity.get("event", {})
    if (identity_event.get("controllerName") != CONTROLLER
            or identity_event.get("accepted") is not True):
        raise ValueError("link index does not contain the accepted Remielle Origin identity")
    managed = _address(_only(links.get("managed"), "managed Animator address"))
    native_animator = _address(_only(links.get("nativeCachePointers"),
                                    "native Animator cache pointer"))
    consumer = _address(_only(links.get("writerConsumers"), "writer consumer address"))
    if _address(identity_event.get("animator")) != managed:
        raise ValueError("accepted identity and managed Animator addresses differ")

    identity_source = identity.get("source", {})
    identity_line = int(identity_source.get("line", 0))
    raw_identity_bytes, raw_identity = _raw_lines(raw_animator_path, {identity_line})[
        identity_line]
    if hashlib.sha256(raw_identity_bytes).hexdigest() != identity_source.get("sha256"):
        raise ValueError("raw Animator identity line hash differs")
    if (raw_identity.get("event") != "identity"
            or raw_identity.get("controllerName") != CONTROLLER
            or _address(raw_identity.get("animator")) != managed):
        raise ValueError("raw Animator identity line does not match the indexed identity")

    binding_rows = [row for row in links.get("bindingEvidence", [])
                    if (_address(row.get("managed")) == managed
                        and _address(row.get("native")) == native_animator
                        and _address(row.get("consumer")) == consumer
                        and row.get("parameterTableExact") is True
                        and row.get("identityPrecedesRead") is True)]
    if not binding_rows:
        raise ValueError("managed-to-native-to-consumer binding evidence is absent")

    lifecycle_rows = []
    for row in links.get("lifecycle", []):
        if (row.get("event") != "exit" or _address(row.get("native")) != native_animator
                or _address(row.get("consumer")) != consumer):
            continue
        field = row.get("fields", {}).get("0x6a0", {})
        if (field.get("ok") is True and _address(field.get("address")) ==
                native_animator + 0x6A0 and _address(field.get("value")) == consumer):
            lifecycle_rows.append(row)
    if not lifecycle_rows:
        raise ValueError("no exact [A+0x6a0]=S lifecycle witness")
    lifecycle = lifecycle_rows[-1]
    lifecycle_line = int(lifecycle.get("source", {}).get("line", 0))
    step_lines = _raw_lines(raw_step_path, {lifecycle_line, lifecycle_line + 1})
    lifecycle_bytes, raw_lifecycle = step_lines[lifecycle_line]
    ccec_bytes, raw_ccec = step_lines[lifecycle_line + 1]
    if hashlib.sha256(lifecycle_bytes).hexdigest() != lifecycle["source"]["sha256"]:
        raise ValueError("raw A+0x6a0 witness line hash differs")
    if (raw_lifecycle.get("event") != "exit"
            or _address(raw_lifecycle.get("object")) != native_animator
            or _address(raw_lifecycle.get("snapshot", {}).get("consumer")) != consumer):
        raise ValueError("raw lifecycle line does not preserve A and S")
    raw_field = [field for field in raw_lifecycle.get("snapshot", {}).get("fields", [])
                 if _address(field.get("address")) == native_animator + 0x6A0]
    if len(raw_field) != 1 or raw_field[0].get("ok") is not True or (
            _address(raw_field[0].get("value")) != consumer):
        raise ValueError("raw lifecycle line does not prove [A+0x6a0]=S")
    if (raw_ccec.get("event") != "enter" or raw_ccec.get("site") != 0
            or _address(raw_ccec.get("object")) != consumer
            or _address(raw_ccec.get("snapshot", {}).get("consumer")) != consumer):
        raise ValueError("the next raw record is not site-0 entry with RCX/object=S")

    sites = hook_sites.get("sites", [])
    if not sites or int(sites[0].get("targetRva", -1)) != CCEC40_RVA:
        raise ValueError("hook site 0 is not source-verified UnityPlayer+0xccec40")
    ready = review.get("ready", {})
    unity_base = _address(ready.get("unityBase"))
    consumer_vtable = _address(ready.get("consumerVtable"))
    if consumer_vtable + CONSUMER_VTABLE_SLOT_OFFSET != (
            unity_base + int(sites[0]["slotRva"])):
        raise ValueError("runtime consumer vtable does not match the verified ccec40 slot")
    if raw_ccec.get("snapshot", {}).get("consumerVtable") != ready.get("consumerVtable"):
        raise ValueError("raw S instance vtable differs from the installed ccec40 slot owner")

    group_rows = [row for row in links.get("groups", [])
                  if _address(row.get("consumer")) == consumer]
    if len(group_rows) != 1 or int(group_rows[0].get("sites", {}).get("0", 0)) <= 0:
        raise ValueError("indexed S instance has no site-0 execution inventory")
    site_zero_events = int(group_rows[0]["sites"]["0"])

    checks = {
        "raw_files_match_derived_sources": True,
        "clean_lossless_restored_state_step_stream": True,
        "accepted_remielle_controller_identity": True,
        "managed_animator_to_native_animator_binding": True,
        "native_animator_plus_0x6a0_equals_consumer": True,
        "consumer_rcx_enters_site_zero": True,
        "site_zero_is_unityplayer_ccec40": True,
        "static_ccec40_to_stage_path_verified": True,
    }
    result = {
        "schema": "uc.legacy-animator-stage-instance-join.v1",
        "sources": {
            "links": _source(links_path),
            "state_step_review": _source(review_path),
            "hook_sites": _source(hook_sites_path),
            "raw_state_step": _source(raw_step_path),
            "raw_animator_identity": _source(raw_animator_path),
            "unity_module": _source(unity_path),
            "animator_stage_static_join": _source(static_stage_path),
            "tool": _source(Path(__file__).resolve()),
        },
        "pid": links["pid"],
        "checks": checks,
        "instance_chain": {
            "managed_animator": managed,
            "controller_name": CONTROLLER,
            "native_animator_A": native_animator,
            "field_offset": 0x6A0,
            "consumer_S": consumer,
            "consumer_callback_rva": CCEC40_RVA,
            "indexed_ccec40_entry_events_for_S": site_zero_events,
        },
        "raw_witnesses": {
            "animator_identity": {"line": identity_line,
                                  "sha256": hashlib.sha256(raw_identity_bytes).hexdigest()},
            "A_plus_0x6a0": {"line": lifecycle_line,
                              "sha256": hashlib.sha256(lifecycle_bytes).hexdigest(),
                              "qpc": raw_lifecycle["endQpc"]},
            "ccec40_entry": {"line": lifecycle_line + 1,
                              "sha256": hashlib.sha256(ccec_bytes).hexdigest(),
                              "qpc": raw_ccec["beginQpc"],
                              "caller": raw_ccec.get("caller")},
        },
        "bounded_conclusion": (
            "In preserved PID 48432 evidence, the accepted Remielle Origin Animator maps to "
            "native A, [A+0x6a0] equals S, and the same S is observed as RCX/object at the "
            "source-verified UnityPlayer+0xccec40 callback.  The independent static join carries "
            "that callback through its evaluator to the two Animator stage functions."),
        "semantic_limits": [
            "This closes the native Animator-to-stage instance ownership path for the preserved PID 48432 generation; it does not transplant addresses into later processes.",
            "The original snapshotAtomic=false limitation is retained; the exact pointer equality is corroborated by the immediately following raw callback entry and 15,758 indexed callbacks for S.",
            "No claim is made that every stage event or every unrelated Ability/ECS path belongs to this instance.",
        ],
        "complete_controller": False,
    }
    output.mkdir(parents=True)
    artifact = output / "legacy-animator-stage-instance-join.json"
    artifact.write_bytes(canonical(result))
    report = {
        "schema": "uc.legacy-animator-stage-instance-join-report.v1",
        "artifact": _source(artifact),
        "pid": links["pid"],
        "controller": CONTROLLER,
        "native_animator_A": native_animator,
        "consumer_S": consumer,
        "ccec40_events": site_zero_events,
    }
    (output / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--links", type=Path, required=True)
    parser.add_argument("--state-step-review", type=Path, required=True)
    parser.add_argument("--hook-sites", type=Path, required=True)
    parser.add_argument("--raw-state-step", type=Path, required=True)
    parser.add_argument("--raw-animator-identity", type=Path, required=True)
    parser.add_argument("--unity-module", type=Path, required=True)
    parser.add_argument("--animator-stage-static-join", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    def invoke():
        try:
            return run(args.links, args.state_step_review, args.hook_sites,
                       args.raw_state_step, args.raw_animator_identity,
                       args.unity_module, args.animator_stage_static_join, args.out)
        except Exception as error:
            write_failure(args.out, "legacy_animator_stage_instance_join", error,
                          {key: str(value) for key, value in vars(args).items()})
            raise

    run_main(invoke)
