import copy
import unittest

from uc.native_manifest import validate_callsite_manifest, validate_exit_manifest


def exit_manifest():
    return {
        "schema": "uc.native-exit-manifest.v1",
        "status": "mechanical-candidate",
        "backend_capability": {"backend_build_hash": "0" * 64},
        "functions": [{
            "function_id": "fixture", "module": "fixture", "entry_rva": 1,
            "runtime_functions": [{"runtime_function_role": "primary"}],
            "normal_exits": [{
                "terminal_semantics": "normal_return",
                "probe_candidates": [{
                    "backend_patch_contract": None,
                    "exit_capture_contract": {
                        "probe_semantics": "pre_instruction",
                        "return_value_stable": True,
                        "xmm_return_stable": True,
                        "stack_restored": False,
                        "caller_return_slot_valid": False,
                        "stack_adjust_remaining": 40,
                        "nonvolatile_restore_remaining": ["rbx"],
                        "relocation_class": "pure_epilogue",
                        "exception_neutral_relocation": None,
                        "contract_evidence": ["fixture"],
                    },
                }],
            }],
            "terminal_sites": [],
            "completeness": {"normal_exit_set_complete": False, "tail_set_complete": False,
                             "cold_fragments_complete": False},
        }],
    }


class ManifestContractTests(unittest.TestCase):
    def test_mechanical_exit_contract(self):
        self.assertEqual(validate_exit_manifest(exit_manifest())["functions"], 1)

    def test_mechanical_cannot_claim_complete(self):
        value = exit_manifest()
        value["functions"][0]["completeness"]["normal_exit_set_complete"] = True
        with self.assertRaisesRegex(ValueError, "mechanical candidate"):
            validate_exit_manifest(value)

    def test_mechanical_cannot_claim_patch_contract(self):
        value = exit_manifest()
        value["functions"][0]["normal_exits"][0]["probe_candidates"][0]["backend_patch_contract"] = "guessed"
        with self.assertRaisesRegex(ValueError, "patch contract"):
            validate_exit_manifest(value)

    def test_partial_manifest_can_promote_one_function_without_promoting_all(self):
        value = exit_manifest()
        value["status"] = "partially-verified"
        value["terminal_verified_functions"] = ["fixture"]
        value["functions"][0]["completeness"] = {"normal_exit_set_complete": True,
            "tail_set_complete": True, "cold_fragments_complete": True}
        self.assertEqual(validate_exit_manifest(value)["status"], "partially-verified")

    def test_exit_contract_must_be_complete(self):
        value = exit_manifest()
        del value["functions"][0]["normal_exits"][0]["probe_candidates"][0]["exit_capture_contract"]["stack_restored"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_exit_manifest(value)

    def test_callsite_contract_forbids_fixed_subtract(self):
        value = {
            "schema": "uc.native-callsite-manifest.v1", "status": "mechanical-candidate", "targets": [],
            "runtime_resolution_contract": {
                "entry_rsp_source": "target-pre-instruction-cpu-context",
                "fixed_subtract_forbidden": True,
                "tail_calls_need_terminal_branch_evidence": True,
            },
        }
        self.assertEqual(validate_callsite_manifest(value)["targets"], 0)
        broken = copy.deepcopy(value)
        broken["runtime_resolution_contract"]["fixed_subtract_forbidden"] = False
        with self.assertRaisesRegex(ValueError, "unsafe"):
            validate_callsite_manifest(broken)


if __name__ == "__main__":
    unittest.main()
