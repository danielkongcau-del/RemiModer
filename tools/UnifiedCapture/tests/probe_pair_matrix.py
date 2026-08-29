"""Run each relocation/ABI case in an isolated local fixture process."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "build/ProbePairProbe.exe"
MODES = (
    "baseline-fault-memory", "probe-fault-memory",
    "baseline-fault-call", "probe-fault-call",
    "probe-epilogue", "probe-long-epilogue", "probe-pop-epilogue", "probe-rsp",
)


def run():
    rows = []
    for mode in MODES:
        process = subprocess.run([str(EXE), mode], capture_output=True, text=True, encoding="utf-8", timeout=20)
        parsed = None
        if process.stdout.strip():
            try:
                parsed = json.loads(process.stdout.splitlines()[-1])
            except json.JSONDecodeError:
                pass
        rows.append({"mode": mode, "returncode": process.returncode, "stdout": process.stdout,
                     "stderr": process.stderr, "result": parsed})
    by_mode = {row["mode"]: row for row in rows}
    checks = {
        "baseline_memory_av_caught": by_mode["baseline-fault-memory"]["result"] is not None and by_mode["baseline-fault-memory"]["result"]["caught"],
        "probe_relocated_memory_av_caught": by_mode["probe-fault-memory"]["result"] is not None and by_mode["probe-fault-memory"]["result"]["caught"],
        "baseline_nested_call_seh_caught": by_mode["baseline-fault-call"]["result"] is not None and by_mode["baseline-fault-call"]["result"]["caught"],
        "probe_relocated_call_seh_caught": by_mode["probe-fault-call"]["result"] is not None and by_mode["probe-fault-call"]["result"]["caught"],
        "epilogue_return_preserved": by_mode["probe-epilogue"]["result"] is not None and by_mode["probe-epilogue"]["result"]["preserved"],
        "long_epilogue_all_instruction_classes_preserved": by_mode["probe-long-epilogue"]["result"] is not None and by_mode["probe-long-epilogue"]["result"]["preserved"],
        "pop_epilogue_in_near_relocated_span_preserved": by_mode["probe-pop-epilogue"]["result"] is not None and by_mode["probe-pop-epilogue"]["result"]["preserved"],
        "target_architectural_rsp_proven": by_mode["probe-rsp"]["result"] is not None and by_mode["probe-rsp"]["result"]["architectural_rsp_proven"],
        "cfg_policy_query_available": all(row["result"] is not None and row["result"].get("cfg_policy_query") is True for row in rows),
        "cet_policy_query_available": all(row["result"] is not None and row["result"].get("cet_user_shadow_stack_policy_query") is True for row in rows),
    }
    result = {"schema": "uc.probe-pair-matrix.v1", "rows": rows, "checks": checks,
              "ok": all(checks.values()), "game_runtime_verified": False,
              "attach_failure_superseded": False}
    output = ROOT / "test-output" / ("probe-pair-" + uuid.uuid4().hex)
    output.mkdir(parents=True)
    report = output / "report.json"
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(report), "ok": result["ok"], "checks": checks}, ensure_ascii=False))
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    run()
