"""Bounded fault/stress tests in our own process; never locates game processes."""
import copy
import ctypes
import json
import struct
import time
import uuid
from pathlib import Path
from native_integration import Host, ROOT, records
from uc.store import inspect_session, read_manifest
from uc.model import file_hash
from uc.model import canonical
from uc.projections import execution_graph

def run():
    root = ROOT / "test-output" / ("robustness-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    results = []
    def case(name, fn, bootstrap_text=None):
        host = Host(root / name, bootstrap_text=bootstrap_text)
        try:
            detail = fn(host)
            results.append({"case": name, "ok": True, "detail": detail})
        except Exception as error:
            results.append({"case": name, "ok": False, "error": repr(error)})
            # Preserve failure and continue independent cases, rather than hide
            # the remaining capability matrix behind the first failed process.
        finally:
            try:
                host.close()
            finally:
                (root / "report.json").write_text(json.dumps({"results": results,
                    "all_passed": all(r["ok"] for r in results), "game_runtime_verified": False},
                    ensure_ascii=False, indent=2), encoding="utf-8")
                print(json.dumps(results[-1], ensure_ascii=False), flush=True)

    def saturation(h):
        plan = h.make_plan(("mutate",), slots=1)
        h.control("apply", plan=plan)
        count = h.invoke("stress", count=2500, threads=4)["calls"]
        status = h.stop()
        rows = records(status["directory"])
        lost = sum(x["events"] for x in status["loss"])
        assert lost > 0 and len(rows) + lost == 2 * count, (len(rows), lost, count)
        assert sum(x["reasons"]["queue_overflow"]["events"] for x in status["loss"]) == lost
        metadata, errors = read_manifest(Path(status["directory"]) / "session.manifest")
        summaries = [r for r in metadata if r["kind"] == "loss_summary"]
        assert not errors and summaries and summaries[-1]["loss"]["events"] == lost
        assert inspect_session(Path(status["directory"]))["storage_complete"]
        return {"original_calls": count, "persisted_events": len(rows), "independent_loss_events": lost}
    case("independent-loss-multithread", saturation)

    def malformed_bootstrap(h):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = h.control("status")
            if status["bootstrap_error"]:
                break
            time.sleep(.05)
        assert status["bootstrap_error"] and status["generation"] == 0
        assert h.control("apply", plan=h.make_plan(("mutate",)))["generation"] == 1
        h.invoke("mutate")
        assert h.stop()["state"] == "STOPPED_CLEAN"
        return {"error_reported": True, "control_remained_available": True, "valid_plan_applied_without_reload": True}
    case("invalid-bootstrap-json-recoverable", malformed_bootstrap, "{invalid")
    case("invalid-bootstrap-schema-recoverable", malformed_bootstrap, "{}")

    def restart(h):
        plan = h.make_plan(("mutate",))
        initial = h.control("apply", plan=plan)
        bad = copy.deepcopy(plan)
        bad["points"][0]["expected_prefix"] = "00" * 32
        try:
            h.control("apply", plan=bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError("bad preparation published")
        assert h.control("status")["generation"] == 1
        h.invoke("mutate")
        old = h.stop()
        restarted = h.control("apply", plan=plan)
        assert restarted["generation"] == 2 and restarted["session_id"] != initial["session_id"]
        h.invoke("mutate")
        new = h.stop()
        assert all(inspect_session(Path(s["directory"]))["storage_complete"] for s in (old, new))
        return {"same_pid": h.info["pid"], "generations": [1, 2], "sessions": [old["session_id"], new["session_id"]]}
    case("failed-prepare-and-session-reuse", restart)

    def reclaim(h):
        plan = h.make_plan(("mutate",))
        for rev in range(25):
            plan["plan_revision"] = rev
            h.control("apply", plan=plan)
            h.invoke("mutate")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = h.control("status")
            if status["resident_generations"] == 1:
                break
            time.sleep(.05)
        assert status["resident_generations"] == 1, status
        end = h.stop()
        assert len(records(end["directory"])) == 50
        return {"activations": 25, "resident_generations": 1, "record_buffer_bytes": status["preallocated_record_bytes"]}
    case("generation-reclamation", reclaim)

    def conflict(h):
        h.control("apply", plan=h.make_plan(("mutate",)))
        h.invoke("mutate")
        h.invoke("conflict")
        h.control("stop")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = h.control("status")
            if any(x["conflict"] for x in status["hooks"]):
                break
            time.sleep(.05)
        assert status["state"] == "DRAIN_PENDING" and any(x["conflict"] for x in status["hooks"])
        assert not inspect_session(Path(status["directory"]))["storage_complete"]
        return {"state": status["state"], "third_party_pointer_not_overwritten": True}
    case("ownership-conflict", conflict)

    def abi(h):
        plan = h.make_plan(("recursive", "mixed", "probe"))
        for p in plan["points"]:
            p["reads"] = []
            if p["id"] == "probe":
                p["backend"] = "gum_probe"
            if p["id"] == "mixed":
                p["reads"] = [{"id": "mixed-struct", "base": "r8", "op": "block", "size": 16,
                               "phase": "enter", "evidence": ["fixture"]}]
        h.control("apply", plan=plan)
        h.invoke("recursive", depth=5)
        assert h.invoke("mixed")["value"] == 16.25
        h.invoke("probe")
        end = h.stop()
        rows = records(end["directory"])
        recursion = [e for e, b in rows if e["point"] == "recursive"]
        assert len(recursion) == 12
        enters = [e for e in recursion if e["kind"] == "enter"]
        assert all(enters[i]["observed_parent"] == enters[i-1]["invocation_id"] for i in range(1, 6))
        probe = [e for e, b in rows if e["point"] == "probe"]
        assert len(probe) == 1 and probe[0]["kind"] == "probe" and "invocation_id" not in probe[0]
        mixed = [(e, b) for e, b in rows if e["point"] == "mixed"]
        e, blob = mixed[0]
        assert struct.unpack("<dQ", blob) == (3.5, 9)
        assert struct.unpack("<d", bytes.fromhex(e["raw_abi"]["xmm"]["0"])[:8])[0] == 1.25
        assert struct.unpack("<f", bytes.fromhex(e["raw_abi"]["xmm"]["1"])[:4])[0] == 2.5
        assert struct.unpack("<d", bytes.fromhex(mixed[1][0]["raw_abi"]["xmm"]["0"])[:8])[0] == 16.25
        graph = execution_graph(end["directory"], root / "gum-graph.json")
        assert graph["observed_nesting_edges"] == 5
        return {"recursive_calls": 6, "probe_events": 1, "xmm_float_double_struct": "verified"}
    case("gum-reentrancy-probe-and-abi", abi)

    def readers_unavailable(h):
        capabilities = h.control("capabilities")["capabilities"]["frozen_readers"]
        assert capabilities == {"available": False, "reason": "target-bound-readers-not-in-public-build"}
        return capabilities
    case("target-bound-readers-explicitly-unavailable", readers_unavailable)

    def live_slot(h):
        plan = h.make_plan(("mutate",))
        point = plan["points"][0]
        point.pop("target_rva")
        point.pop("expected_prefix")
        point.update(target_resolution="live-slot", expected_prefix_from_module_file=32)
        assert h.control("apply", plan=plan)["generation"] == 1
        h.invoke("mutate")
        assert h.control("apply", plan=plan)["generation"] == 2
        h.invoke("mutate")
        end = h.stop()
        assert len(records(end["directory"])) == 4
        return {"source": "live slot + verified module file", "reapply_uses_owned_original": True}
    case("live-slot-resolution", live_slot)

    def disconnected_receipt(h):
        plan = h.make_plan(("mutate",))
        raw = canonical({"request_id": "disconnect-apply", "command": "apply", "plan": plan})
        with open(rf"\\.\pipe\UnifiedCapture.{h.info['pid']}", "r+b", buffering=0) as pipe:
            pipe.write(struct.pack("<I", len(raw)) + raw)
            time.sleep(.05)
        assert h.control("apply", request_id="disconnect-apply", plan=plan)["generation"] == 1
        h.invoke("mutate")
        assert h.stop()["generation"] == 1
        return {"lost_response_retry_generation": 1, "control_disconnect_does_not_stop_capture": True}
    case("disconnect-and-idempotent-receipt", disconnected_receipt)

    def gum_exception(h):
        plan = h.make_plan(("gum_raise",))
        plan["points"][0]["reads"] = []
        h.control("apply", plan=plan)
        assert h.invoke("gum_raise")["caught"]
        h.control("stop")
        time.sleep(.15)
        status = h.control("status")
        # Gum does not promise paired leave delivery on arbitrary SEH unwind.
        # If it supplies no leave, retain resources and make incompleteness visible.
        if status["state"] == "STOPPED_CLEAN":
            rows = records(status["directory"])
            assert len(rows) == 2
        else:
            assert status["state"] == "DRAIN_PENDING" and status["in_flight"] == 1
            assert not inspect_session(Path(status["directory"]))["storage_complete"]
        return {"native_exception_caught": True, "state": status["state"], "in_flight": status["in_flight"]}
    case("gum-SEH-unwind-accounting", gum_exception)

    def probe_exception(h):
        plan = h.make_plan(("gum_raise",))
        plan["points"][0].update(backend="gum_probe", reads=[])
        h.control("apply", plan=plan)
        assert h.invoke("gum_raise")["caught"]
        end = h.stop()
        rows = records(end["directory"])
        assert len(rows) == 1 and rows[0][0]["kind"] == "probe"
        assert "invocation_id" not in rows[0][0]
        return {"native_exception_caught": True, "instruction_events": 1, "invented_leave_events": 0}
    case("probe-SEH-without-fabricated-leave", probe_exception)

    def module_epoch(h):
        plan = h.make_plan(("mutate",))
        plan["modules"]["dependency"] = {"image": "FixtureModule.dll", "sha256": file_hash(ROOT / "build/FixtureModule.dll")}
        receipt = h.control("apply", request_id="wait-module", plan=plan)
        assert receipt["state"] == "WAITING_MODULE"
        h.invoke("load_dependency")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status = h.control("status")
            if status["generation"] == 1:
                break
            time.sleep(.05)
        assert status["generation"] == 1, status
        assert h.control("apply", request_id="wait-module", plan=plan)["generation"] == 1
        h.invoke("mutate")
        h.invoke("unload_dependency")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = h.control("status")
            if status["state"] == "MODULE_REBIND_PENDING":
                break
            time.sleep(.05)
        assert status["state"] == "MODULE_REBIND_PENDING", status
        h.invoke("load_dependency")
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status = h.control("status")
            if status["generation"] == 2:
                break
            time.sleep(.05)
        assert status["generation"] == 2, status
        h.invoke("mutate")
        end = h.stop()
        assert len(records(end["directory"])) == 4
        return {"waiting_then_activation": True, "reload_generation": 2, "scope": "non-hooked dependent module"}
    case("module-wait-and-rebind", module_epoch)

    def storage_error(h):
        h.control("apply", plan=h.make_plan(("mutate",)))
        directory = Path(h.control("status")["directory"])
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        lock = kernel.CreateFileW(str(directory / "session.manifest"), 0x80000000, 1, None, 3, 0, None)
        assert lock != ctypes.c_void_p(-1).value
        try:
            h.invoke("mutate")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = h.control("status")
                if status["storage_error"]:
                    break
                time.sleep(.05)
            assert status["storage_error"], status
            h.control("stop")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = h.control("status")
                if all(not x["owned"] for x in status["hooks"]):
                    break
                time.sleep(.05)
            assert status["state"] == "DRAIN_PENDING" and status["storage_error"]
            assert all(not x["owned"] for x in status["hooks"]), status
        finally:
            kernel.CloseHandle(lock)
        return {"storage_error": status["storage_error"], "hooks_cleaned_independently": True, "clean_seal_not_claimed": True}
    case("storage-failure-and-cleanup", storage_error)

    def crash(h):
        h.control("apply", plan=h.make_plan(("mutate",)))
        h.invoke("mutate", count=20)
        directory = h.control("status")["directory"]
        time.sleep(1.1)
        h.process.kill()  # This Popen-created fixture only; never discovers another PID.
        h.process.wait(timeout=5)
        inspection = inspect_session(Path(directory))
        assert not inspection["storage_complete"] and "session_tail_unknown" in inspection["errors"]
        return {"valid_chunks_retained": len(inspection["chunks"]), "tail_unknown": True}
    case("abrupt-fixture-exit", crash)

    def duration(h):
        plan = h.make_plan(("mutate",), slots=512)
        h.control("apply", plan=plan)
        start = time.monotonic()
        calls = 0
        # Test boundary, not a capture timeout: DLL never receives a duration.
        while time.monotonic() - start < 16.1:
            h.invoke("mutate", count=20)
            calls += 20
            time.sleep(.15)
        assert h.control("status")["state"] == "RUNNING"
        h.control("mark", label="after-15-seconds-and-200-events")
        end = h.stop()
        rows = records(end["directory"])
        assert len(rows) == 2 * calls > 200 and not sum(x["events"] for x in end["loss"])
        return {"elapsed_seconds": time.monotonic()-start, "calls": calls, "events": len(rows), "automatic_stop": False}
    case("no-legacy-duration-or-count-cutoff", duration)
    print(json.dumps({"report": str(root / "report.json"), "cases": len(results)}), flush=True)
    return 0 if all(r["ok"] for r in results) else 1

if __name__ == "__main__":
    raise SystemExit(run())
