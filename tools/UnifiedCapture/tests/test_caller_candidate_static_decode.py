from dataclasses import dataclass
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caller_candidate_static_decode import decode_candidates


@dataclass(frozen=True)
class Function:
    begin: int
    end: int
    unwind_rva: int


class Image:
    def __init__(self):
        self.by_start = {0x100: Function(0x100, 0x110, 0x900)}

    def decode(self, function):
        return {"all_declared_bytes_decoded": True, "instructions": [{
            "rva": 0x108, "size": 5, "bytes": "e8", "mnemonic": "call",
            "operands": "target", "groups": ["call"], "regs_read": [],
            "regs_write": [], "direct_target_rva": 0x200}]}

    def cfg(self, function):
        return {"reachable_instruction_rvas": [0x108], "edges": [], "terminals": []}

    def bytes_at(self, rva, size):
        return b"x" * size


def test_priority_callsite_is_verified_against_observed_target():
    profile = {"priority_candidates": [{"module": "unity", "point": "p",
        "caller_runtime_function": {"begin_rva": 0x100}, "callsite_rva": 0x108,
        "dominant_action_label": "TASK", "action_callbacks": 2,
        "total_callbacks": 2}]}
    plan = {"schema": "uc.capture-plan.v1", "points": [{"id": "p", "rva": 0x200}]}
    result = decode_candidates(profile, plan, {"unity": Image()})
    assert result["summary"] == {"priority_callsites": 1, "runtime_functions": 1,
        "fully_decoded_functions": 1, "direct_target_verified_callsites": 1,
        "indirect_runtime_verified_callsites": 0}
    assert result["functions"][0]["candidate_callsites"][0][
        "direct_target_matches_observed_point"] is True


class IndirectImage(Image):
    def decode(self, function):
        return {"all_declared_bytes_decoded": True, "instructions": [{
            "rva": 0x108, "size": 6, "bytes": "ff90", "mnemonic": "call",
            "operands": "qword ptr [rax + 0x108]", "groups": ["call"],
            "regs_read": [], "regs_write": [], "direct_target_rva": None}]}


def test_indirect_callsite_uses_runtime_return_address_proof():
    profile = {"priority_candidates": [{"module": "unity", "point": "p",
        "caller_runtime_function": {"begin_rva": 0x100}, "callsite_rva": 0x108,
        "callsite_status": "OBSERVED_RETURN_ADDRESS_RESOLVES_TO_CALL",
        "dominant_action_label": "TASK", "action_callbacks": 2,
        "total_callbacks": 2}]}
    plan = {"schema": "uc.capture-plan.v1", "points": [{"id": "p", "rva": 0x200}]}
    result = decode_candidates(profile, plan, {"unity": IndirectImage()})
    callsite = result["functions"][0]["candidate_callsites"][0]
    assert callsite["callsite_kind"] == "indirect"
    assert callsite["direct_target_matches_observed_point"] is False
    assert callsite["runtime_return_address_resolves_to_callsite"] is True
    assert result["summary"]["indirect_runtime_verified_callsites"] == 1
