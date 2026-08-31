from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_upstream_invoker_join import run


ROOT = Path(__file__).resolve().parents[3]


def test_authoritative_api_callsite_joins_exact_runtime_caller(tmp_path: Path) -> None:
    api = ROOT / "extracted/analysis/behavior-observer/animator-api-usage-20260828-v3/animator-api-usage.json"
    runtime = ROOT / "extracted/analysis/controller-exact-closure-runtime-20260831-p38144-v2/exact-analysis-v2/controller-exact-closure-runtime-analysis.json"
    plan = ROOT / "extracted/analysis/controller-exact-closure-plan-20260831-v3/capture-plan.controller-exact-closure.json"
    if not all(path.is_file() for path in (api, runtime, plan)):
        return
    result = run(api, runtime, plan, tmp_path / "join.json")
    assert result["static_callsite"]["callsite_rva"] == 0xACE052
    assert result["static_callsite"]["continuation_rva"] == 0xACE055
    assert result["static_callsite"]["invoker_rva"] == 0x4E30
    assert result["checks"]["selected_api_to_invoker_to_bridge_same_invocation_closed"]
