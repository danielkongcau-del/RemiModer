"""Resumable multi-entry qualification, compilation and activation using one observer."""
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
from uc.site_qualification import validate_site_qualification


def prepare_apply(pid: int, qualification_path: Path, manifest_path: Path,
                  plan_path: Path, output: Path):
    qualification = json.loads(qualification_path.read_text(encoding="utf-8-sig"))
    source_plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    validate_site_qualification(qualification)
    intended = {"schema": "uc.entry-orchestration-intent.v1", "pid": pid,
        "unit_id": source_plan["plan_id"], "armed_label": "ENTRY_UNIT_ARMED",
        "finish_label": "ENTRY_UNIT_ACTION_COMPLETE",
        "qualification": {"path": str(qualification_path), "sha256": file_hash(qualification_path)},
        "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "source_plan": {"path": str(plan_path), "sha256": file_hash(plan_path)},
        "qualification_request_id": str(uuid.uuid4()), "apply_request_id": str(uuid.uuid4()),
        "armed_mark_request_id": str(uuid.uuid4()), "finish_mark_request_id": str(uuid.uuid4()),
        "stop_request_id": str(uuid.uuid4())}
    intent_path = output / "intent.json"
    if output.exists():
        intended = json.loads(intent_path.read_text(encoding="utf-8-sig"))
        if intended["pid"] != pid or intended["qualification"]["sha256"] != file_hash(qualification_path) or \
                intended["manifest"]["sha256"] != file_hash(manifest_path) or \
                intended["source_plan"]["sha256"] != file_hash(plan_path):
            raise ValueError("existing entry intent belongs to different inputs/process")
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
        response = json.loads(evidence_path.read_text(encoding="utf-8-sig"))["response"]
    if not response.get("ok"):
        raise RuntimeError(response)
    derived = output / "derived"
    if not derived.exists():
        apply_entries(manifest_path, plan_path, evidence_path, derived)
    derived_report = json.loads((derived / "report.json").read_text(encoding="utf-8-sig"))
    compiled_plan = json.loads(Path(derived_report["entry_plan"]["path"]).read_text(encoding="utf-8-sig"))
    activation_path = output / "activation-response.json"
    if not activation_path.exists():
        activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=compiled_plan)
        # WAITING_* parks the plan pending module availability; poll until the
        # idempotent apply returns a real generation before calling it success.
        while activation.get("ok") and "generation" not in activation:
            status = request(pid, "status")
            if not status.get("waiting_plan") and status.get("bootstrap_error"):
                raise RuntimeError({"error": "apply failed while waiting for modules",
                                    "bootstrap_error": status["bootstrap_error"],
                                    "state": status.get("state")})
            # Replay the idempotent apply only once the parked plan resolved,
            # so the retry returns the real receipt instead of the reserved
            # EXECUTION_UNCERTAIN placeholder.
            if not status.get("waiting_plan"):
                activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=compiled_plan)
                continue
            time.sleep(.5)
        save_new(activation_path, activation)
    else:
        activation = json.loads(activation_path.read_text(encoding="utf-8-sig"))
    if not activation.get("ok") or "generation" not in activation:
        raise RuntimeError({"error": "activation did not produce a generation",
                            "activation": activation})
    armed_path = output / "armed-mark-response.json"
    if not armed_path.exists():
        armed = request(pid, "mark", request_id=intended["armed_mark_request_id"], label=intended["armed_label"])
        save_new(armed_path, armed)
    else:
        armed = json.loads(armed_path.read_text(encoding="utf-8-sig"))
    if not armed.get("ok"):
        raise RuntimeError(armed)
    result = {"schema": "uc.entry-orchestration-result.v1", "pid": pid,
        "unit_id": intended["unit_id"], "generation": activation["generation"],
        "plan_hash": activation["plan_hash"], "logical_observations": len(compiled_plan["observations"]),
        "qualification_sites": len(response["sites"]), "session_id": activation.get("session_id"),
        "directory": activation.get("directory"), "state": "ENTRY_UNIT_RUNNING_NO_AUTOMATIC_STOP",
        "exit_probes_activated": False}
    result_path = output / "result.json"
    if not result_path.exists():
        save_new(result_path, result)
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare-apply")
    prepare.add_argument("--pid", type=int, required=True)
    prepare.add_argument("--qualification", type=Path, required=True)
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--plan", type=Path, required=True)
    prepare.add_argument("--out", type=Path, required=True)
    finish = sub.add_parser("finish")
    finish.add_argument("--pid", type=int, required=True)
    finish.add_argument("--run", type=Path, required=True)
    finish.add_argument("--wait-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.command == "prepare-apply":
        run_main(prepare_apply, args.pid, args.qualification.resolve(), args.manifest.resolve(),
                 args.plan.resolve(), args.out.resolve())
    else:
        result = run_main(finish_capture, args.pid, args.run, args.wait_seconds)
        if not result.get("clean"):
            raise SystemExit(1)
