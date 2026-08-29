"""Resumable local D0 qualification -> process-bound entry-plan activation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
import uuid

from capturectl import request
from p1_apply_site_qualification import run as apply_qualification
from uc.cli import run_main
from uc.model import canonical, file_hash
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification


def save_new(path: Path, value):
    with path.open("xb") as stream:
        stream.write(canonical(value))


def save_finish_attempt(output: Path, value):
    """Append an immutable, monotonically sequenced finish attempt.

    Wall clocks and mtimes can move backwards or be changed by file copies.
    Exclusive creation resolves concurrent finish clients without overwriting
    either result.
    """
    prefix = "finish-attempt-"
    sequence = 1
    for path in output.glob(prefix + "*.json"):
        token = path.stem[len(prefix):].split("-", 1)[0]
        if token.isdigit():
            sequence = max(sequence, int(token) + 1)
    while True:
        path = output / f"{prefix}{sequence:020d}.json"
        try:
            save_new(path, value)
            return path
        except FileExistsError:
            sequence += 1


def prepare_apply(pid: int, qualification_path: Path, manifest_path: Path,
                  function_id: str, output: Path):
    qualification = json.loads(qualification_path.read_text(encoding="utf-8-sig"))
    validate_site_qualification(qualification)
    intended = {"schema": "uc.d0-orchestration-intent.v1", "pid": pid,
        "qualification": {"path": str(qualification_path), "sha256": file_hash(qualification_path)},
        "manifest": {"path": str(manifest_path), "sha256": file_hash(manifest_path)},
        "function_id": function_id,
        "unit_id": "D0-set-ability-special-entry", "armed_label": "D0_ARMED",
        "finish_label": "D0_ACTION_COMPLETE",
        "qualification_request_id": str(uuid.uuid4()), "apply_request_id": str(uuid.uuid4()),
        "armed_mark_request_id": str(uuid.uuid4()), "finish_mark_request_id": str(uuid.uuid4()),
        "stop_request_id": str(uuid.uuid4())}
    intent_path = output / "intent.json"
    if output.exists():
        if not intent_path.exists():
            raise ValueError("existing output has no resumable intent")
        intended = json.loads(intent_path.read_text(encoding="utf-8-sig"))
        if intended["pid"] != pid or intended["qualification"]["sha256"] != file_hash(qualification_path) or \
                intended["manifest"]["sha256"] != file_hash(manifest_path) or intended["function_id"] != function_id:
            raise ValueError("existing D0 intent belongs to different inputs/process")
    else:
        output.mkdir(parents=True)
        save_new(intent_path, intended)
    evidence_path = output / "site-qualification-evidence.json"
    if not evidence_path.exists():
        response = request(pid, "qualify-sites", request_id=intended["qualification_request_id"],
                           qualification=qualification)
        envelope = {"schema": "uc.target-site-qualification-evidence.v1",
                    "request": qualification, "response": response}
        save_new(evidence_path, envelope)
        if not response.get("ok"):
            raise RuntimeError(response)
    else:
        response = json.loads(evidence_path.read_text(encoding="utf-8-sig"))["response"]
        if not response.get("ok"):
            raise RuntimeError(response)
    derived = output / "derived"
    if not derived.exists():
        apply_qualification(manifest_path, evidence_path, function_id, derived)
    report = json.loads((derived / "report.json").read_text(encoding="utf-8-sig"))
    plan_path = Path(report["entry_plan"]["path"])
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))
    compiled = compile_probe_pair(plan, verify_sources=True)
    activation_path = output / "activation-response.json"
    if not activation_path.exists():
        activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=plan)
        # WAITING_* means the plan is parked pending module availability — the
        # observer answers ok:true without a generation. Poll until it resolves
        # (or fail loudly) so a persisted "success" can never mean "not active".
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
                activation = request(pid, "apply", request_id=intended["apply_request_id"], plan=plan)
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
        armed = request(pid, "mark", request_id=intended["armed_mark_request_id"],
                        label=intended.get("armed_label", "D0_ARMED"))
        save_new(armed_path, armed)
    else:
        armed = json.loads(armed_path.read_text(encoding="utf-8-sig"))
    if not armed.get("ok"):
        raise RuntimeError(armed)
    summary = {"schema": "uc.d0-orchestration-result.v1", "pid": pid,
        "qualification_request_id": intended["qualification_request_id"],
        "apply_request_id": intended["apply_request_id"], "qualification_sites": len(response["sites"]),
        "plan_hash": compiled.plan_hash, "generation": activation["generation"],
        "state": "ENTRY_D0_RUNNING_NO_AUTOMATIC_STOP", "behavior_events_required": True,
        "exit_probe_activated": False, "output": str(output),
        "session_id": activation.get("session_id"), "directory": activation.get("directory"),
        "armed_mark_recorded": True}
    summary_path = output / "result.json"
    if not summary_path.exists():
        save_new(summary_path, summary)
    print(json.dumps(summary, ensure_ascii=False))


def finish_capture(pid: int, output: Path, wait_seconds: float = 30.0):
    """Mark the user-completed action and request a clean, resumable stop."""
    output = output.resolve()
    intended = json.loads((output / "intent.json").read_text(encoding="utf-8-sig"))
    if intended["pid"] != pid:
        raise ValueError("D0 run belongs to a different process")
    finish_mark_path = output / "finish-mark-response.json"
    if not finish_mark_path.exists():
        marked = request(pid, "mark", request_id=intended["finish_mark_request_id"],
                         label=intended.get("finish_label", "D0_ACTION_COMPLETE"))
        save_new(finish_mark_path, marked)
    else:
        marked = json.loads(finish_mark_path.read_text(encoding="utf-8-sig"))
    if not marked.get("ok"):
        raise RuntimeError(marked)
    stop_path = output / "stop-response.json"
    if not stop_path.exists():
        stopped = request(pid, "stop", request_id=intended["stop_request_id"])
        save_new(stop_path, stopped)
    else:
        stopped = json.loads(stop_path.read_text(encoding="utf-8-sig"))
    if not stopped.get("ok"):
        raise RuntimeError(stopped)
    deadline = time.monotonic() + wait_seconds
    while True:
        status = request(pid, "status")
        # A forced stop is terminal too.  It is deliberately not "clean", but
        # waiting for the whole client deadline cannot improve it and only
        # hides the actual terminal outcome from the operator.
        if status.get("state") in ("STOPPED_CLEAN", "STOPPED_FORCED") \
                or status.get("storage_error") or time.monotonic() >= deadline:
            break
        time.sleep(.05)
    clean = status.get("state") == "STOPPED_CLEAN"
    result = {"schema": "uc.d0-finish-result.v1", "pid": pid,
        "state": status.get("state"), "generation": status.get("generation"),
        "session_id": status.get("session_id"), "directory": status.get("directory"),
        "storage_error": status.get("storage_error"), "loss": status.get("loss"),
        "admission_window_drops": status.get("admission_window_drops"),
        "clean": clean}
    if not clean:
        result["failure_attribution"] = {
            "DRAIN_PENDING": "callbacks or sealing still in flight; re-run finish or use a forced stop",
            "MODULE_REBIND_PENDING": "a bound module was reloaded; rebind and requalify",
            "STOPPED_FORCED": "stop required a forced drain; treat evidence as unclean",
            "STORAGE_FAILED": "evidence persistence failed; admission is closed and the session cannot be sealed cleanly",
        }.get(status.get("state"), "session ended without a clean seal; inspect the session directory")
    # Persist every attempt so analyzers can attribute non-clean intermediate
    # endings. The immutable conventional result is created only once clean.
    result_path = output / "finish-result.json"
    save_finish_attempt(output, result)
    if clean and not result_path.exists():
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
    prepare.add_argument("--function-id", required=True)
    prepare.add_argument("--out", type=Path, required=True)
    finish = sub.add_parser("finish")
    finish.add_argument("--pid", type=int, required=True)
    finish.add_argument("--run", type=Path, required=True)
    finish.add_argument("--wait-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.command == "prepare-apply":
        run_main(prepare_apply, args.pid, args.qualification.resolve(), args.manifest.resolve(),
                 args.function_id, args.out.resolve())
    else:
        result = run_main(finish_capture, args.pid, args.run, args.wait_seconds)
        if not result.get("clean"):
            raise SystemExit(1)
