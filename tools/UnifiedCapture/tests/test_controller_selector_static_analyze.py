from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_selector_static_analyze import run


ROOT = Path(__file__).resolve().parents[3]


def test_preserved_runtime_closes_both_remielle_selector_outcomes(tmp_path: Path) -> None:
    native = ROOT / "extracted/analysis/p1a-remielle-native-behavior-trees.json"
    runtime = ROOT / "extracted/analysis/behavior-observer/session-42892-task-join-20260827-verified/join.json"
    layout = ROOT / "extracted/dump-x-xa.cs"
    if not all(path.is_file() for path in (native, runtime, layout)):
        return
    result = run(native, runtime, layout, tmp_path / "join.json")
    assert [row["serialized_task_index"] for row in result["selectors"]] == [3, 45]
    assert [[branch["observed_dispatch_count"] for branch in row["branches"]]
            for row in result["selectors"]] == [[21, 17], [9, 4]]
    assert all(weight["serialized_value"] == 1.0
               for row in result["selectors"] for weight in row["weights"])
    assert result["checks"]["selector_choice_edges_closed"]
    assert not result["limits"]["entity_identity_promoted"]
