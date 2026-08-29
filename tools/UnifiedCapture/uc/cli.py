"""Uniform CLI exit discipline.

Exit codes across local tools:
  0  success
  1  the target observer explicitly rejected the request (ok:false)
  2  an internal error (bad inputs, corrupt evidence, environment) — message
     on stderr, full traceback only with UC_TRACEBACK=1

Without this, every failure is an uncaught traceback and callers cannot
distinguish "the observer said no" from "our own tooling broke".
"""
from __future__ import annotations

import os
import sys
import traceback


def run_main(fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - single reporting point by design
        print(f"error: {type(error).__name__}: {error}", file=sys.stderr)
        if os.environ.get("UC_TRACEBACK"):
            traceback.print_exc()
        raise SystemExit(2) from error
    if isinstance(result, dict) and result.get("ok") is False:
        raise SystemExit(1)
    return result


def write_failure(planned_output, stage: str, error: Exception, inputs: dict):
    """Persist why a derivation failed, next to where its output would have gone.

    Derivation outputs are immutable once created, so a failed run leaves no
    directory at all — and until now, no durable trace of the reason. The
    failure artifact keeps qualification failures attributable offline.
    """
    from pathlib import Path
    import uuid
    from .model import canonical
    base = Path(planned_output)
    base.parent.mkdir(parents=True, exist_ok=True)
    path = Path(str(base) + ".failure.json")
    if path.exists():
        path = Path(str(base) + f".failure-{uuid.uuid4().hex}.json")
    record = {"schema": "uc.derivation-failure.v1", "stage": stage,
              "error": f"{type(error).__name__}: {error}", "inputs": inputs}
    with path.open("xb") as stream:
        stream.write(canonical(record))
    return path
