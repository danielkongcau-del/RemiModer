"""Isolate target-process qualification failures without publishing capture.

Each source-qualified site is installed, inspected and restored independently.
The tool refuses to continue unless the observer returns to an idle, hook-free,
generation-zero state after every attempt.  Results are immutable diagnostic
evidence; they are not a replacement for the final exact-set qualification.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from capturectl import request
from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash
from uc.site_qualification import validate_site_qualification


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _idle_status(pid: int, request_id: str) -> dict[str, Any]:
    status = request(pid, "status", request_id=request_id)
    if (not status.get("ok") or status.get("state") != "IDLE"
            or status.get("generation") != 0 or status.get("hooks")
            or status.get("in_flight") != 0):
        raise RuntimeError(f"observer did not return to idle after qualification: {status}")
    return status


def run(pid: int, qualification_path: Path, out: Path,
        request_prefix: str) -> dict[str, Any]:
    if out.exists():
        raise FileExistsError(f"output is immutable: {out}")
    source = _load(qualification_path)
    validate_site_qualification(source)
    out.mkdir(parents=True)
    attempts = []
    _idle_status(pid, request_prefix + "-status-before")
    for index, site in enumerate(source["sites"]):
        single = copy.deepcopy(source)
        single["qualification_id"] = f'{source["qualification_id"]}:isolate:{index}'
        single["sites"] = [site]
        response = request(pid, "qualify-sites", request_id=f"{request_prefix}-{index}",
                           qualification=single)
        status = _idle_status(pid, f"{request_prefix}-status-{index}")
        attempt = {
            "index": index, "site_id": site["id"], "request": single,
            "response": response,
            "post_status": {key: status.get(key) for key in (
                "state", "generation", "hooks", "in_flight", "storage_error")},
        }
        attempts.append(attempt)
        (out / f"attempt-{index:02d}.json").write_bytes(canonical(attempt))
    failures = [row for row in attempts if not row["response"].get("ok")]
    report = {
        "schema": "uc.qualification-isolation-report.v1",
        "pid": pid,
        "source": {"path": str(qualification_path),
                   "sha256": file_hash(qualification_path)},
        "attempts": len(attempts), "succeeded": len(attempts) - len(failures),
        "failed": len(failures),
        "failed_sites": [{"index": row["index"], "site_id": row["site_id"],
                          "error": row["response"].get("error")}
                         for row in failures],
        "capture_generation_published": False,
        "all_post_attempt_states_idle": True,
        "exact_set_qualification_still_required": True,
    }
    (out / "report.json").write_bytes(canonical(report))
    print(json.dumps(report, ensure_ascii=False))
    return report


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--request-prefix", default="qualification-isolate")
    args = parser.parse_args()
    try:
        return run(args.pid, args.qualification.resolve(), args.out.resolve(),
                   args.request_prefix)
    except Exception as error:
        write_failure(args.out, "qualification_isolate", error, {
            "pid": args.pid, "qualification": str(args.qualification)})
        raise


if __name__ == "__main__":
    run_main(main)
