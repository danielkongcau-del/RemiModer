from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_exact_closure_plan import POINTS, _exact


def test_exact_caller_is_module_relative_and_unbounded_in_time() -> None:
    row = _exact(0x1234, ["authority"])
    assert row["exact_callers"] == [{"module": "game", "return_rva": 0x1234,
                                      "evidence": ["authority"]}]
    assert "duration" not in row


def test_shared_high_frequency_api_parent_is_not_a_capture_point() -> None:
    ids = {row[0] for row in POINTS}
    assert "SelectedEncryptedApiTarget@0xacdfe0" not in ids
    assert "AnimatorFixedUpdate.invoker@0x4e30" in ids
