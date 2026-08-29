"""Isolate fixed Gum's exception behavior from all UnifiedCapture implementation.

Reports failures, never converts an unhandled exception into successful validation.
Only own six child processes are created; no game process access.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from uc.model import file_hash


def main():
    root = ROOT / "test-output" / ("gum-exceptions-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    binary = ROOT / "build/GumExceptionProbe.exe"
    results = []
    for mode in ("baseline", "probe", "attach"):
        for exception in ("seh", "cpp"):
            command = [str(binary), mode, exception]
            try:
                p = subprocess.run(command, text=True, capture_output=True, timeout=15,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                result = {"mode": mode, "exception": exception, "exit_code": p.returncode,
                          "exit_hex": hex(p.returncode & 0xffffffff), "stdout": p.stdout, "stderr": p.stderr,
                          "native_exception_preserved": p.returncode == 0}
            except subprocess.TimeoutExpired as e:
                result = {"mode": mode, "exception": exception, "timeout": True,
                          "native_exception_preserved": False, "error": str(e)}
            results.append(result)
            print(json.dumps(result), flush=True)
    report = {"gum": "17.17.0", "architecture": "windows-x64", "binary_sha256": file_hash(binary),
              "source_sha256": file_hash(ROOT / "native/gum_exception_probe.cpp"),
              "platform_dll_loaded": False, "game_runtime_verified": False, "results": results,
              "all_exceptions_preserved": all(r["native_exception_preserved"] for r in results)}
    (root / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(root / "report.json")
    return 0 if report["all_exceptions_preserved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
