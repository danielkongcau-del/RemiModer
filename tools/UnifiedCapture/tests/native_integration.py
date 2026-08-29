"""Exercise only our own FixtureHost. No attachment to the game or XXMI."""
from __future__ import annotations
import copy
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
from uc.model import digest, validate
from uc.store import decode_chunk, inspect_session

class Host:
    def __init__(self, root, bootstrap_text=None):
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

    def make_plan(self, names=("mutate", "gum", "block", "float", "state", "raise"), revision=17, slots=32):
        info = self.info
        p = {"schema": "uc.capture-plan.v1", "plan_id": "synthetic-fixture-NOT-game-evidence", "plan_revision": revision,
             "modules": {"fixture": {"image": info["module"], "sha256": info["sha256"]}},
             "sources": {"fixture": {"path": info["module_path"], "sha256": info["sha256"]}},
             "resources": {"slots_per_point": slots, "max_record_bytes": 4096}, "points": []}
        for name in names:
            target = info["targets"][name]
            point = {"id": name, "module": "fixture", "rva": target["rva"], "expected_prefix": target["expected_prefix"],
                     "evidence": ["fixture"], "backend": "slot" if target["abi"] else "gum_attach", "reads": []}
            if target["abi"]:
                point.update(abi=target["abi"], target_module="fixture", target_rva=target["target_rva"])
            base = "arg0" if target["abi"] else "rcx"
            point["reads"].append({"id": "value", "op": "scalar", "base": base, "width": 8, "evidence": ["fixture"]})
            if name == "state":
                point["reads"].append({"id": "output", "op": "block", "base": "arg3", "size": 40,
                                       "phase": "leave", "evidence": ["fixture"]})
            p["points"].append(point)
        validate(p, verify_sources=True)
        return p

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
        checks.append("original slot/Gum functions, float NaN bits, state output and SEH preserved")
        host.invoke("block")
        assert host.control("status")["in_flight"] == 1
        second = copy.deepcopy(first)
        second["plan_revision"] = 18
        second["points"][0]["reads"].append({"id": "count", "op": "scalar", "base": "arg0", "offset": 8,
                                             "width": 8, "evidence": ["fixture"]})
        assert host.control("apply", plan=second)["generation"] == 2
        host.invoke("mutate")
        assert host.control("apply", plan=first)["generation"] == 3
        host.invoke("gum")
        host.control("stop")
        pending = host.control("status")
        assert pending["state"] == "DRAIN_PENDING" and pending["in_flight"] == 1
        host.invoke("release")
        stopped = host.stop()
        checks.append("17->18->17 generation, old in-flight pin, asynchronous drain and late leave")
        inspection = inspect_session(Path(stopped["directory"]))
        assert inspection["storage_complete"], inspection
        rows = records(stopped["directory"])
        block = [e for e, _ in rows if e["point"] == "block"]
        assert len(block) == 2 and {e["generation"] for e in block} == {1}
        assert {e["kind"] for e in block} == {"enter", "leave"}
        float_events = [e for e, _ in rows if e["point"] == "float"]
        assert float_events[0]["semantic_interpretation"]["validated_argument_bits"][2]["bits"] == 0x7fc01234
        assert float_events[0]["raw_abi"]["register_mask"] == 0
        gum_events = [e for e, _ in rows if e["point"] == "gum"]
        assert gum_events[0]["raw_abi"]["registers"]["rcx"] == host.info["object"]
        assert gum_events[0]["raw_abi"]["xmm_mask"] == 65535
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
