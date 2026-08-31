from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_completion_contract import CORE_CLAIMS, completion_from_claims


def _claims(status: str = "CLOSED") -> list[dict]:
    return [{"id": claim_id, "scope": "CORE_REQUIRED", "status": status}
            for claim_id, _ in CORE_CLAIMS]


def test_finite_completion_is_reachable() -> None:
    complete, open_ids = completion_from_claims(_claims())
    assert complete is True
    assert open_ids == []


def test_closed_opaque_is_a_core_terminal_but_environment_unavailable_is_not() -> None:
    claims = _claims("CLOSED_OPAQUE")
    claims[8]["status"] = "ENVIRONMENT_UNAVAILABLE"
    complete, open_ids = completion_from_claims(claims)
    assert complete is False
    assert open_ids == ["C09"]


def test_denominator_cannot_silently_grow_or_shrink() -> None:
    with pytest.raises(ValueError, match="denominator"):
        completion_from_claims(_claims()[:-1])
    extra = _claims() + [{"id": "C15", "scope": "CORE_REQUIRED",
                          "status": "CLOSED"}]
    with pytest.raises(ValueError, match="denominator"):
        completion_from_claims(extra)
