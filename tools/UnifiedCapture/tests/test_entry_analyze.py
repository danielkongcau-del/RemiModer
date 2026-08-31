from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from entry_analyze import _caller_module, coverage_contains_window


def test_coverage_must_contain_the_entire_marked_window() -> None:
    rows = [
        {"point": "p", "begin_qpc": 10, "end_qpc": 20, "complete": True},
        {"point": "other", "begin_qpc": 0, "end_qpc": 100, "complete": True},
    ]
    assert coverage_contains_window(rows, "p", [12, 18])
    assert not coverage_contains_window(rows, "p", [5, 18])
    assert not coverage_contains_window(rows, "p", [12, 25])
    assert not coverage_contains_window(rows, "p", [21, 22])
    assert not coverage_contains_window(rows, "p", None)


def test_incomplete_or_malformed_coverage_is_not_accepted() -> None:
    rows = [
        {"point": "p", "begin_qpc": 0, "end_qpc": 100, "complete": False},
        {"point": "p", "begin_qpc": "0", "end_qpc": 100, "complete": True},
    ]
    assert not coverage_contains_window(rows, "p", [10, 20])


def test_caller_address_is_resolved_across_all_bound_modules() -> None:
    class Image:
        def __init__(self, size):
            self.size_of_image = size

    bindings = {"game": {"module_base": 0x1000}, "unity": {"module_base": 0x5000}}
    images = {"game": Image(0x1000), "unity": Image(0x2000)}
    alias, binding, image = _caller_module(0x5500, bindings, images)
    assert alias == "unity"
    assert binding is bindings["unity"]
    assert image is images["unity"]
    assert _caller_module(0x9000, bindings, images) is None
