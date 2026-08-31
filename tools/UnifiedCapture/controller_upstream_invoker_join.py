"""Join the selected Unity API target to the Animator invoker using static and runtime evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from uc.cli import run_main, write_failure
from uc.model import canonical, file_hash


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _source(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": file_hash(path)}


def run(api_usage_path: Path, exact_runtime_path: Path, capture_plan_path: Path,
        output: Path) -> dict[str, Any]:
    api_usage_path, exact_runtime_path, capture_plan_path, output = [path.resolve() for path in (
        api_usage_path, exact_runtime_path, capture_plan_path, output)]
    if output.exists():
        raise FileExistsError(f"output is immutable: {output}")
    api, runtime, plan = (_load(api_usage_path), _load(exact_runtime_path),
                          _load(capture_plan_path))
    if api.get("schema") != "zzz.animator-api-usage.v1":
        raise ValueError("unsupported Animator API authority")
    if runtime.get("schema") != "uc.controller-exact-closure-runtime-analysis.v1":
        raise ValueError("unsupported exact runtime analysis")
    if plan.get("plan_id") != "controller-exact-closure-v1":
        raise ValueError("unexpected exact capture plan")
    runtime_sources = runtime.get("sources", {})
    if runtime_sources.get("animator_api_usage", {}).get("sha256") != file_hash(api_usage_path):
        raise ValueError("runtime analysis was not derived from the supplied API authority")
    if runtime_sources.get("capture_plan", {}).get("sha256") != file_hash(capture_plan_path):
        raise ValueError("runtime analysis was not derived from the supplied capture plan")

    invoke = api["invoke"]
    api_rva, invoker_rva = invoke["gameTargetRva"], invoke["invokerRva"]
    bridge_rva = invoke["bridgeCodeRva"]
    function = next((row for row in api.get("functions", []) if row.get("rva") == api_rva), None)
    if function is None or not function.get("allDeclaredBytesDecoded"):
        raise ValueError("selected API function is not completely decoded")
    instructions = function["instructions"]
    indirect_calls = [row for row in instructions if row.get("mnemonic") == "call" and
                      row.get("operands") == "qword ptr [rdi + 0x10]"]
    if len(indirect_calls) != 1:
        raise ValueError("selected API function does not have exactly one invoker-field call")
    call = indirect_calls[0]
    call_size = len(bytes.fromhex(call["bytes"]))
    continuation_rva = call["rva"] + call_size
    if invoke.get("methodInvokerOffset") != 0x10:
        raise ValueError("API authority invoker offset disagrees with decoded call")

    invoker_point = next((row for row in plan.get("points", [])
                          if row.get("id") == "AnimatorFixedUpdate.invoker@0x4e30"), None)
    if invoker_point is None or invoker_point.get("rva") != invoker_rva:
        raise ValueError("capture plan does not observe the selected invoker entry")
    observed = runtime["animator_invoker"]
    if observed.get("selected_exact_caller_return_rva") != continuation_rva:
        raise ValueError("runtime exact caller is not the selected API call continuation")
    if observed.get("selected_bridge_rva") != bridge_rva:
        raise ValueError("runtime selected bridge disagrees with static API authority")
    if not observed.get("same_invocation_child_dispatch_observed"):
        raise ValueError("invoker-to-bridge same-invocation evidence is absent")

    result = {
        "schema": "uc.controller-upstream-invoker-join.v1",
        "sources": {"animator_api_usage": _source(api_usage_path),
                    "exact_runtime_analysis": _source(exact_runtime_path),
                    "capture_plan": _source(capture_plan_path)},
        "static_callsite": {
            "api_target_rva": api_rva,
            "function_end_rva": function["declaredEnd"],
            "callsite_rva": call["rva"],
            "call_bytes": call["bytes"],
            "call_operands": call["operands"],
            "continuation_rva": continuation_rva,
            "invoker_field_offset": invoke["methodInvokerOffset"],
            "invoker_rva": invoker_rva,
        },
        "runtime_join": {
            "observed_invoker_entry_rva": invoker_point["rva"],
            "observed_exact_caller_return_rva": observed["selected_exact_caller_return_rva"],
            "selected_bridge_rva": observed["selected_bridge_rva"],
            "selected_bridge_count": observed["selected_bridge_count"],
            "selected_bridge_action_window_count": observed["selected_bridge_action_window_count"],
        },
        "checks": {
            "api_function_completely_decoded": True,
            "single_invoker_field_call": True,
            "call_continuation_matches_runtime_exact_caller": True,
            "capture_point_matches_static_invoker": True,
            "invoker_to_selected_bridge_same_invocation_observed": True,
            "selected_api_to_invoker_to_bridge_same_invocation_closed": True,
        },
        "scope": {
            "claim": "selected Unity API target to Animator invoker to selected bridge same-invocation causality",
            "complete_controller": False,
            "no_new_runtime_capture_required": True,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(result))
    print(json.dumps({"schema": result["schema"], "output": _source(output),
                      "callsite_rva": call["rva"], "continuation_rva": continuation_rva,
                      "closed": True}, ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-usage", type=Path, required=True)
    parser.add_argument("--exact-runtime", type=Path, required=True)
    parser.add_argument("--capture-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    def execute() -> dict[str, Any]:
        try:
            return run(args.api_usage, args.exact_runtime, args.capture_plan, args.out)
        except Exception as error:
            write_failure(args.out, "controller_upstream_invoker_join", error,
                          {"api_usage": str(args.api_usage),
                           "exact_runtime": str(args.exact_runtime),
                           "capture_plan": str(args.capture_plan)})
            raise
    run_main(execute)
