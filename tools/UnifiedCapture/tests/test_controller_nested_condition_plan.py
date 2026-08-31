from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controller_nested_condition_plan import _caller_contract
from uc.native_manifest import NativePE


ROOT = Path(__file__).resolve().parents[3]
GAME = ROOT / "miHoYo Launcher/games/ZenlessZoneZero Game/GameAssembly.dll"


def test_two_observed_callers_share_the_conditional_evaluator_abi() -> None:
    if not GAME.is_file():
        return
    image = NativePE(GAME)
    rows = [_caller_contract(image, rva) for rva in (0x1F21899C, 0x1F218A55)]
    assert all(all(row["checks"].values()) for row in rows)
    assert [row["callsite_rva"] for row in rows] == [0x1F218996, 0x1F218A4F]
