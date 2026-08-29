"""Exercise only our own FixtureHost. No attachment to the game or XXMI."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from capturectl import request
from uc.model import canonical, digest, validate
from uc.store import decode_chunk, inspect_session

class Host:
    def __init__(self, root, bootstrap_text=None):
        self.root = Path(root)
        env = os.environ.copy()
        env.pop("UC_FIXTURE_BOOTSTRAP", None)
        if bootstrap_text is not None:
            root.mkdir(parents=True, exist_ok=True)
            path = root / "fixture-bootstrap.json"
            path.write_text(bootstrap_text, encoding="utf-8")
            env["UC_FIXTURE_BOOTSTRAP"] = str(path)
        self.process = subprocess.Popen([str(ROOT / "build/FixtureHost.exe"), str(ROOT / "build/UnifiedCapture.dll"), str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"fixture startup failed: {self.process.stderr.read()}")
        self.info = json.loads(line)
        for _ in range(60):
            try:
                self.control("status")
                break
            except OSError:
                if self.process.poll() is not None:
                    raise RuntimeError("fixture exited while waiting for control")
                time.sleep(.05)
        else:
            raise RuntimeError("control did not become ready")

    def control(self, command, **kwargs):
        result = request(self.info["pid"], command, **kwargs)
        if not result.get("ok"):
            raise RuntimeError(str(result))
        return result

    def invoke(self, op, **kwargs):
        self.process.stdin.write(json.dumps({"op": op, **kwargs}) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            code = self.process.wait(timeout=5)
            raise RuntimeError(f"fixture exited: code={code:#x} stderr={self.process.stderr.read()}")
        result = json.loads(line)
        if "error" in result:
            raise RuntimeError(str(result))
        return result

    def make_plan(self, names=("mutate", "gum", "float", "state", "raise"), revision=17, slots=32):
        info = self.info
        p = {"schema": "uc.capture-plan.v1", "plan_id": "synthetic-fixture-NOT-game-evidence", "plan_revision": revision,
             "modules": {"fixture": {"image": info["module"], "sha256": info["sha256"]}},
             "sources": {"fixture": {"path": info["module_path"], "sha256": info["sha256"]}},
             "resources": {"slots_per_point": slots, "max_record_bytes": 4096}, "points": []}
        for name in names:
            target = info["targets"][name]
            point = {"id": name, "module": "fixture", "rva": target["rva"], "expected_prefix": target["expected_prefix"],
                     "evidence": ["fixture"], "backend": "slot" if target["abi"] else "gum_probe", "reads": []}
            if target["abi"]:
                point.update(abi=target["abi"], target_module="fixture", target_rva=target["target_rva"])
            base = "arg0" if target["abi"] else "rcx"
            read = {"id": "value", "op": "scalar", "base": base, "width": 8, "evidence": ["fixture"]}
            if not target["abi"]:
                read["phase"] = "enter"
            point["reads"].append(read)
            if name == "state":
                point["reads"].append({"id": "output", "op": "block", "base": "arg3", "size": 40,
                                       "phase": "leave", "evidence": ["fixture"]})
            p["points"].append(point)
        validate(p, verify_sources=True)
        return p

    def make_probe_pair_plan(self, observations=("pair_block",), revision=17, slots=64):
        """Build a v2 plan for the explicit entry/exit assembly fixtures.

        Items may be operation names or ``(logical_id, operation_name)`` pairs,
        allowing tests to verify exact physical-site sharing without another
        plan builder.
        """
        definitions = {
            "pair": ("pair_entry", "pair_exit"),
            "pair_recursive": ("pair_recursive_entry", "pair_recursive_exit"),
            "pair_block": ("pair_block_entry", "pair_block_exit"),
        }
        normalized = [(item, item) if isinstance(item, str) else tuple(item) for item in observations]
        if not normalized or any(len(item) != 2 or item[1] not in definitions for item in normalized):
            raise ValueError("unknown/empty probe-pair fixture observation")

        def patch_contract(probe_rva=None):
            value = {"backend_build_hash": "23f5185116d83ca7b7c1f2e069f0c590e0bcdfcbd8374543343bcf4075770475",
                     "redirect_kind": "near", "required_redirect_span": 5, "relocated_span": 5,
                     "fault_in_relocated_span_test": "passed-own-fixture",
                     "architectural_rsp_test": "passed-own-fixture", "cet_cfg_test": "target-runtime-required"}
            if probe_rva is not None:
                value["probe_rva"] = probe_rva
            return value

        exit_contract = {"probe_semantics": "pre_instruction", "return_value_stable": True,
                         "xmm_return_stable": True, "stack_restored": True,
                         "caller_return_slot_valid": True, "stack_adjust_remaining": 0,
                         "nonvolatile_restore_remaining": [], "relocation_class": "pure_epilogue",
                         "exception_neutral_relocation": True, "contract_evidence": ["assembly-fixture"]}
        functions = []
        for operation in dict.fromkeys(operation for _, operation in normalized):
            entry_name, exit_name = definitions[operation]
            entry, exit_site = self.info["targets"][entry_name], self.info["targets"][exit_name]
            functions.append({"function_id": operation, "module": "fixture", "entry_rva": entry["rva"],
                "runtime_functions": [{"runtime_function_role": "primary"}],
                "normal_exits": [{"exit_site_id": f"{operation}-ret", "terminal_semantics": "normal_return",
                    "terminal_semantics_verified": True, "probe_candidates": [{"probe_rva": exit_site["rva"],
                        "expected_bytes": exit_site["expected_prefix"][:10],
                        "verified_source_prefix": exit_site["expected_prefix"], "incoming_edges_complete": True,
                        "backend_patch_contract": patch_contract(exit_site["rva"]),
                        "exit_capture_contract": exit_contract}]}],
                "terminal_sites": [], "completeness": {"normal_exit_set_complete": True,
                    "tail_set_complete": True, "cold_fragments_complete": True}})
        manifest = {"schema": "uc.native-exit-manifest.v1", "status": "three-way-verified",
                    "backend_capability": {"backend_build_hash": patch_contract()["backend_build_hash"]},
                    "functions": functions}
        manifest_path = self.root / "fixture-exit-manifest.json"
        manifest_path.write_bytes(canonical(manifest))
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        plan = {"schema": "uc.capture-plan.v2", "plan_id": "native-probe-pair-fixture",
                "plan_revision": revision,
                "modules": {"fixture": {"image": self.info["module"], "sha256": self.info["sha256"]}},
                "sources": {"fixture": {"path": self.info["module_path"], "sha256": self.info["sha256"]}},
                "resources": {"event_slots_per_observation": slots, "call_frames_per_function": 16,
                              "thread_nesting_limit": 64, "max_record_bytes": 256},
                "physical_site_policy": {"exact_site_sharing": "share-one-listener-multiple-logical-subscriptions",
                                         "partial_overlap": "reject"}, "observations": []}
        for logical_id, operation in normalized:
            entry_name, _ = definitions[operation]
            target = self.info["targets"][entry_name]
            reads = [{"id": "receiver", "base": "rcx", "op": "scalar", "width": 8,
                      "phase": "enter", "evidence": ["fixture"]}]
            if operation == "pair":
                reads.append({"id": "receiver-after", "base": "entry:rcx", "op": "scalar", "width": 8,
                              "phase": "leave", "evidence": ["fixture"]})
            plan["observations"].append({"id": logical_id, "backend": "gum_function_probe_pair",
                "module": "fixture", "entry": {"rva": target["rva"],
                    "expected_prefix": target["expected_prefix"], "backend_patch_contract": patch_contract(),
                    "reads": reads},
                "exit_capture_requirement": "return_value",
                "native_exit_manifest": {"path": str(manifest_path), "sha256": manifest_sha,
                                         "function_id": operation}, "evidence": ["fixture"]})
        return plan

    def stop(self, timeout=10):
        self.control("stop")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.control("status")
            if status["state"] == "STOPPED_CLEAN":
                return status
            if status["storage_error"]:
                raise RuntimeError(status["storage_error"])
            time.sleep(.05)
        raise AssertionError(f"stop remains pending: {status}")

    def close(self):
        if self.process.poll() is None:
            try:
                self.invoke("quit")
            except (OSError, RuntimeError):
                self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass

def records(directory):
    result = []
    for path in sorted(Path(directory).glob("*.ucb")):
        _, rows = decode_chunk(path.read_bytes())
        result.extend((event, blob) for _, _, event, blob in rows)
    return sorted(result, key=lambda row: row[0]["event_id"])

def main():
    root = ROOT / "test-output" / ("native-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    checks = []
    host = Host(root)
    try:
        first = host.make_plan()
        applied = host.control("apply", request_id="apply-first", plan=first)
        assert applied["generation"] == 1
        assert applied["plan_hash"] == digest(first)
        assert host.control("apply", request_id="apply-first", plan=first) == applied
        checks.append("native compile hash matches Python; mutation retry does not reactivate")
        host.invoke("mutate")
        host.invoke("gum")
        assert host.invoke("float")["value"] == 0x7fc01236
        host.invoke("state")
        assert host.invoke("raise")["caught"]
        checks.append("original slot/instruction-probe functions, float NaN bits, state output and SEH preserved")
        second = copy.deepcopy(first)
        second["plan_revision"] = 18
        second["points"][0]["reads"].append({"id": "count", "op": "scalar", "base": "arg0", "offset": 8,
                                             "width": 8, "evidence": ["fixture"]})
        assert host.control("apply", plan=second)["generation"] == 2
        host.invoke("mutate")
        assert host.control("apply", plan=first)["generation"] == 3
        host.invoke("gum")
        stopped = host.stop()
        checks.append("17->18->17 activation generations remain distinct")
        inspection = inspect_session(Path(stopped["directory"]))
        assert inspection["storage_complete"], inspection
        rows = records(stopped["directory"])
        float_events = [e for e, _ in rows if e["point"] == "float"]
        assert float_events[0]["semantic_interpretation"]["validated_argument_bits"][2]["bits"] == 0x7fc01234
        assert float_events[0]["raw_abi"]["register_mask"] == 0
        gum_events = [e for e, _ in rows if e["point"] == "gum"]
        assert len(gum_events) == 2 and {e["kind"] for e in gum_events} == {"probe"}
        assert {e["generation"] for e in gum_events} == {1, 3}
        assert all(e["raw_abi"]["registers"]["rcx"] == host.info["object"] for e in gum_events)
        assert all(e["raw_abi"]["xmm_mask"] == 65535 for e in gum_events)
        assert all(not item["events"] for item in stopped["loss"])
        checks.append("native compressed chunks independently verified; raw ABI/semantic values separated")
        result = {"ok": True, "checks": checks, "status": stopped, "inspection": inspection,
                  "events": len(rows), "game_runtime_verified": False}
    except Exception as error:
        result = {"ok": False, "checks": checks, "error": repr(error), "game_runtime_verified": False}
        raise
    finally:
        host.close()
        if "result" in locals():
            with (root / "report.json").open("x", encoding="utf-8") as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2)
            print(json.dumps({"report": str(root / "report.json"), "ok": result["ok"], "checks": checks}, ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()
