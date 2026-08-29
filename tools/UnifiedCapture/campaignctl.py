"""Run a multi-plan entry campaign from one target-process qualification.

The campaign keeps qualification, activation generations, marks and stop
receipts immutable on disk.  It never injects a module and never enables an
automatic capture deadline or event-count stop.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
import uuid

from capturectl import request
from d0ctl import finish_capture, save_new
from p1_apply_entry_qualification import run as apply_entries
from uc.cli import run_main
from uc.model import file_hash
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def _load_ref(ref: dict, what: str):
    path = Path(ref["path"]).resolve()
    if file_hash(path) != ref["sha256"]:
        raise ValueError(f"{what} changed: {path}")
    return path, json.loads(path.read_text(encoding="utf-8-sig"))


def _load_campaign(path: Path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if value.get("schema") != "uc.entry-campaign.v1" or not value.get("units"):
        raise ValueError("entry campaign schema/units")
    ids = set()
    for unit in value["units"]:
        uid = unit.get("id")
        if not isinstance(uid, str) or not uid or uid in ids or Path(uid).name != uid:
            raise ValueError("campaign unit id is empty, duplicated, or not path-safe")
        ids.add(uid)
        _load_ref(unit["source_plan"], f"campaign unit {uid}")
    _load_ref(value["manifest"], "campaign manifest")
    _, qualification = _load_ref(value["qualification"], "campaign qualification")
    validate_site_qualification(qualification)
    return value


def qualify(pid: int, campaign_path: Path, output: Path):
    campaign_path = campaign_path.resolve()
    campaign = _load_campaign(campaign_path)
    _, qualification = _load_ref(campaign["qualification"], "campaign qualification")
    intended = {"schema": "uc.entry-campaign-intent.v1", "pid": pid,
        "campaign": {"path": str(campaign_path), "sha256": file_hash(campaign_path)},
        "qualification_request_id": str(uuid.uuid4()),
        "finish_mark_request_id": str(uuid.uuid4()), "stop_request_id": str(uuid.uuid4()),
        "finish_label": "ENTRY_CAMPAIGN_COMPLETE"}
    intent_path = output / "intent.json"
    if output.exists():
        if not intent_path.exists():
            raise ValueError("existing campaign output has no resumable intent")
        intended = json.loads(intent_path.read_text(encoding="utf-8-sig"))
        if intended["pid"] != pid or intended["campaign"]["sha256"] != file_hash(campaign_path):
            raise ValueError("existing campaign run belongs to different inputs/process")
    else:
        output.mkdir(parents=True)
        save_new(intent_path, intended)
    evidence_path = output / "site-qualification-evidence.json"
    if not evidence_path.exists():
        response = request(pid, "qualify-sites", request_id=intended["qualification_request_id"],
                           qualification=qualification)
        save_new(evidence_path, {"schema": "uc.target-site-qualification-evidence.v1",
                                 "request": qualification, "response": response})
    else:
        envelope = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
        response = envelope["response"]
    if not response.get("ok") or response.get("capture_generation_published"):
        raise RuntimeError(response)
    if {row["id"] for row in response.get("sites", [])} != {row["id"] for row in qualification["sites"]}:
        raise ValueError("qualification response site set differs from campaign request")
    result = {"schema": "uc.entry-campaign-qualification-result.v1", "pid": pid,
        "campaign_id": campaign["campaign_id"], "qualification_sites": len(response["sites"]),
        "capture_generation_published": False, "state": "CAMPAIGN_QUALIFIED_NOT_ARMED",
        "units": [unit["id"] for unit in campaign["units"]]}
    result_path = output / "qualification-result.json"
    if not result_path.exists():
        save_new(result_path, result)
    print(json.dumps(result, ensure_ascii=False))
    return result


def _run_inputs(pid: int, output: Path):
    output = output.resolve()
    intent = json.loads((output / "intent.json").read_text(encoding="utf-8-sig"))
    if intent.get("schema") != "uc.entry-campaign-intent.v1" or intent["pid"] != pid:
        raise ValueError("campaign run belongs to a different process")
    campaign_path = Path(intent["campaign"]["path"])
    if file_hash(campaign_path) != intent["campaign"]["sha256"]:
        raise ValueError("campaign changed after qualification")
    campaign = _load_campaign(campaign_path)
    evidence_path = output / "site-qualification-evidence.json"
    if not evidence_path.exists():
        raise ValueError("campaign has not been target-qualified")
    return output, intent, campaign, evidence_path


def _unit(campaign: dict, unit_id: str):
    matches = [unit for unit in campaign["units"] if unit["id"] == unit_id]
    if len(matches) != 1:
        raise ValueError(f"unknown campaign unit: {unit_id}")
    return matches[0]


def apply_unit(pid: int, output: Path, unit_id: str):
    output, _, campaign, evidence_path = _run_inputs(pid, output)
    unit = _unit(campaign, unit_id)
    for prior in campaign["units"]:
        if prior["order"] >= unit["order"]:
            continue
        if not (output / "units" / prior["id"] / "complete-mark-response.json").exists():
            raise ValueError(f"prior campaign unit is not marked complete: {prior['id']}")
    manifest_path, _ = _load_ref(campaign["manifest"], "campaign manifest")
    plan_path, _ = _load_ref(unit["source_plan"], f"campaign unit {unit_id}")
    unit_dir = output / "units" / unit_id
    intent_path = unit_dir / "intent.json"
    intended = {"schema": "uc.entry-campaign-unit-intent.v1", "pid": pid,
        "unit_id": unit_id, "source_plan": unit["source_plan"],
        "apply_request_id": str(uuid.uuid4()), "armed_mark_request_id": str(uuid.uuid4()),
        "complete_mark_request_id": str(uuid.uuid4()),
        "armed_label": unit["armed_label"], "complete_label": unit["complete_label"]}
    if unit_dir.exists():
        intended = json.loads(intent_path.read_text(encoding="utf-8-sig"))
        if intended["pid"] != pid or intended["source_plan"]["sha256"] != file_hash(plan_path):
            raise ValueError("existing unit intent belongs to different inputs/process")
    else:
        unit_dir.mkdir(parents=True)
        save_new(intent_path, intended)
    derived = unit_dir / "derived"
    if not derived.exists():
        apply_entries(manifest_path, plan_path, evidence_path, derived,
                      exit_requirement="none", allow_qualification_superset=True)
    report = json.loads((derived / "report.json").read_text(encoding="utf-8-sig"))
    compiled_path = Path(report["entry_plan"]["path"])
    plan = json.loads(compiled_path.read_text(encoding="utf-8-sig"))
    compiled = compile_probe_pair(plan, verify_sources=True)
    activation_path = unit_dir / "activation-response.json"
    if not activation_path.exists():
        activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=plan)
        while activation.get("ok") and "generation" not in activation:
            status = request(pid, "status")
            if not status.get("waiting_plan") and status.get("bootstrap_error"):
                raise RuntimeError(status)
            if not status.get("waiting_plan"):
                activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=plan)
                continue
            time.sleep(.5)
        save_new(activation_path, activation)
    else:
        activation = json.loads(activation_path.read_text(encoding="utf-8-sig"))
    if not activation.get("ok") or "generation" not in activation:
        raise RuntimeError(activation)
    armed_path = unit_dir / "armed-mark-response.json"
    if not armed_path.exists():
        armed = request(pid, "mark", request_id=intended["armed_mark_request_id"],
                        label=intended["armed_label"])
        save_new(armed_path, armed)
    else:
        armed = json.loads(armed_path.read_text(encoding="utf-8-sig"))
    if not armed.get("ok"):
        raise RuntimeError(armed)
    result = {"schema": "uc.entry-campaign-unit-result.v1", "pid": pid, "unit_id": unit_id,
        "generation": activation["generation"], "plan_hash": compiled.plan_hash,
        "logical_observations": len(plan["observations"]), "state": "UNIT_RUNNING_NO_AUTOMATIC_STOP",
        "armed_label": intended["armed_label"], "complete_label": intended["complete_label"],
        "session_id": activation.get("session_id"), "directory": activation.get("directory")}
    result_path = unit_dir / "result.json"
    if not result_path.exists():
        save_new(result_path, result)
    print(json.dumps(result, ensure_ascii=False))
    return result


def complete_unit(pid: int, output: Path, unit_id: str):
    output, _, campaign, _ = _run_inputs(pid, output)
    _unit(campaign, unit_id)
    unit_dir = output / "units" / unit_id
    intended = json.loads((unit_dir / "intent.json").read_text(encoding="utf-8-sig"))
    if not (unit_dir / "activation-response.json").exists():
        raise ValueError("campaign unit was not activated")
    path = unit_dir / "complete-mark-response.json"
    if not path.exists():
        response = request(pid, "mark", request_id=intended["complete_mark_request_id"],
                           label=intended["complete_label"])
        save_new(path, response)
    else:
        response = json.loads(path.read_text(encoding="utf-8-sig"))
    if not response.get("ok"):
        raise RuntimeError(response)
    result = {"schema": "uc.entry-campaign-unit-completion.v1", "pid": pid,
              "unit_id": unit_id, "label": intended["complete_label"],
              "generation": response.get("generation"), "state": "UNIT_MARKED_COMPLETE"}
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    qualify_cmd = sub.add_parser("qualify")
    qualify_cmd.add_argument("--pid", type=int, required=True)
    qualify_cmd.add_argument("--campaign", type=Path, required=True)
    qualify_cmd.add_argument("--out", type=Path, required=True)
    apply_cmd = sub.add_parser("apply")
    apply_cmd.add_argument("--pid", type=int, required=True)
    apply_cmd.add_argument("--run", type=Path, required=True)
    apply_cmd.add_argument("--unit", required=True)
    complete_cmd = sub.add_parser("complete")
    complete_cmd.add_argument("--pid", type=int, required=True)
    complete_cmd.add_argument("--run", type=Path, required=True)
    complete_cmd.add_argument("--unit", required=True)
    finish_cmd = sub.add_parser("finish")
    finish_cmd.add_argument("--pid", type=int, required=True)
    finish_cmd.add_argument("--run", type=Path, required=True)
    finish_cmd.add_argument("--wait-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.command == "qualify":
        run_main(qualify, args.pid, args.campaign.resolve(), args.out.resolve())
    elif args.command == "apply":
        run_main(apply_unit, args.pid, args.run.resolve(), args.unit)
    elif args.command == "complete":
        run_main(complete_unit, args.pid, args.run.resolve(), args.unit)
    else:
        result = run_main(finish_capture, args.pid, args.run.resolve(), args.wait_seconds)
        if not result.get("clean"):
            raise SystemExit(1)
