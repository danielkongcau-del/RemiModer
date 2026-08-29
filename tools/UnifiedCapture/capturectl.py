"""Local control and offline evidence commands; never injects a process."""
from __future__ import annotations
import argparse
from collections import defaultdict, deque
import ctypes
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import time
import uuid
from uc.model import validate, canonical
from uc.cli import run_main
from uc.probe_pair import compile_probe_pair
from uc.site_qualification import validate_site_qualification
from uc.store import inspect_session, decode_chunk_file
from uc.index import EvidenceIndex
from uc.projections import execution_graph, legacy_projection

def request(pid, command, *, request_id=None, **fields):
    if os.name != "nt":
        raise OSError("native control is Windows-only")
    name = rf"\\.\pipe\UnifiedCapture.{int(pid)}"
    raw = canonical({"request_id": request_id or str(uuid.uuid4()), "command": command, **fields})
    # A request channel, not an external attach/inject operation.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    deadline = time.monotonic() + 3
    while True:
        try:
            if not kernel.WaitNamedPipeW(name, 100):
                raise ctypes.WinError(ctypes.get_last_error())
            stream = open(name, "r+b", buffering=0)
            break
        except OSError as error:
            if getattr(error, "winerror", None) not in (2, 121, 231) or time.monotonic() >= deadline:
                raise
            time.sleep(.01)
    with stream:
        stream.write(struct.pack("<I", len(raw)) + raw)
        def receive(size):
            chunks = bytearray()
            while len(chunks) < size:
                part = stream.read(size - len(chunks))
                if not part:
                    raise ConnectionError("control response truncated")
                chunks += part
            return bytes(chunks)
        length, = struct.unpack("<I", receive(4))
        if length > 64 * 1024 * 1024:
            raise ValueError("invalid control response length")
        payload = receive(length)
        # Explicit drain acknowledgement: DisconnectNamedPipe discards unread
        # output, while FlushFileBuffers may block forever on a stalled client.
        stream.write(b"\x06")
        return json.loads(payload)

def export_trace(directory, destination):
    """Chrome trace projection accepted by local Perfetto; source remains .ucb."""
    inspection = inspect_session(directory)
    manifests = __import__("uc.store", fromlist=["read_manifest"]).read_manifest(Path(directory) / "session.manifest")[0]
    header = next(r for r in manifests if r.get("kind") == "session")
    freq = header.get("qpc_frequency")
    if not freq:
        raise ValueError("source QPC frequency missing; no guessed clock conversion")
    enters, leaves, instants = {}, defaultdict(deque), []
    for chunk in inspection["chunks"]:
        _, records = decode_chunk_file(Path(directory) / chunk["file"])
        for _, _, event, _ in records:
            kind = event.get("kind")
            if kind not in ("enter", "leave", "probe", "mark"):
                continue
            if kind == "enter" and event.get("invocation_id") is not None:
                key = (event.get("point"), event["invocation_id"], event.get("tid"))
                if key in enters:
                    raise ValueError(f"duplicate invocation enter in sealed evidence: {key}")
                enters[key] = event
            elif kind == "leave" and event.get("invocation_id") is not None:
                leaves[(event.get("point"), event["invocation_id"], event.get("tid"))].append(event)
            else:
                instants.append(event)
    durations, unpaired = [], 0
    for key, enter in enters.items():
        leave = leaves[key].popleft() if leaves[key] else None
        if leave is not None and leave["qpc"] >= enter["qpc"]:
            durations.append((enter, leave))
        else:
            unpaired += 1
            instants.append(enter)
            if leave is not None:
                instants.append(leave)
    unpaired_leaves = sum(len(pending) for pending in leaves.values())
    for pending in leaves.values():
        instants.extend(pending)
    with Path(destination).open("x", encoding="utf-8") as stream:
        stream.write('{"traceEvents":[')
        first = True
        def emit(row):
            nonlocal first
            if not first:
                stream.write(",")
            stream.write(json.dumps(row, ensure_ascii=False))
            first = False
        pid = header.get("pid", 0)
        for enter, leave in durations:
            # Paired durations only when both halves were observed; timing is
            # observed evidence, never reconstructed from unmatched halves.
            emit({"name": enter.get("point", "enter"), "cat": "observed-paired-duration", "pid": pid,
                  "tid": enter.get("tid", 0), "ts": enter["qpc"] * 1_000_000 / freq,
                  "dur": (leave["qpc"] - enter["qpc"]) * 1_000_000 / freq, "ph": "X",
                  "args": {"event_id": enter["event_id"], "leave_event_id": leave["event_id"],
                           "generation": enter.get("generation"), "invocation_id": enter.get("invocation_id")}})
        for event in instants:
            kind = event.get("kind")
            emit({"name": event.get("point", kind), "cat": "observed-not-inferred", "pid": pid,
                  "tid": event.get("tid", 0), "ts": event["qpc"] * 1_000_000 / freq,
                  "ph": "i", "s": "t", "args": {"event_id": event["event_id"], "kind": kind,
                  "generation": event.get("generation"), "invocation_id": event.get("invocation_id")}})
        for mark in (r for r in manifests if r.get("kind") == "user_mark"):
            emit({"name": mark["label"], "cat": "user-mark-not-native-semantics", "ph": "i", "s": "g",
                  "pid": pid, "tid": 0, "ts": mark["qpc"] * 1_000_000 / freq})
        stream.write('],"displayTimeUnit":"ms","pairedDurations":')
        stream.write(json.dumps({"paired": len(durations), "unpaired_enters": unpaired,
                                 "unpaired_leaves": unpaired_leaves}))
        stream.write(',"sourceInspection":')
        stream.write(json.dumps(inspection, ensure_ascii=False))
        stream.write("}")
    return {"projection": str(destination), "source_mutated": False,
            "paired_durations": len(durations), "unpaired_enters": unpaired,
            "unpaired_leaves": unpaired_leaves}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for cmd in ("capabilities", "start", "status", "stop", "mark", "apply", "qualify-sites"):
        item = sub.add_parser(cmd)
        item.add_argument("--pid", type=int, required=True)
        item.add_argument("--request-id")
        if cmd == "apply":
            item.add_argument("plan", type=Path)
        if cmd == "mark":
            item.add_argument("label")
        if cmd == "qualify-sites":
            item.add_argument("qualification", type=Path)
            item.add_argument("--out", type=Path, required=True)
        if cmd == "stop":
            item.add_argument("--drain", action="store_true", required=True)
            item.add_argument("--force", action="store_true",
                              help="terminal unclean seal for wedged frames; unresolved hooks/resources "
                                   "remain resident and the process cannot be reactivated")
    item = sub.add_parser("validate")
    item.add_argument("plan", type=Path)
    item.add_argument("--verify-sources", action="store_true")
    item.add_argument("--pid", type=int, help="also prepare/resolve in the already loaded observer, without hooks")
    item = sub.add_parser("select-plan")
    item.add_argument("plan", type=Path)
    item.add_argument("--destination", type=Path, default=Path(__file__).resolve().parent / "build/bootstrap.json")
    item = sub.add_parser("inspect")
    item.add_argument("directory", type=Path)
    for cmd in ("index", "import-legacy"):
        item = sub.add_parser(cmd)
        item.add_argument("source", type=Path)
        item.add_argument("--db", type=Path, required=True)
    item = sub.add_parser("query")
    item.add_argument("db", type=Path)
    item.add_argument("sql")
    for cmd in ("export-trace", "export-graph", "export-legacy"):
        item = sub.add_parser(cmd)
        item.add_argument("directory", type=Path)
        item.add_argument("destination", type=Path)
        if cmd == "export-legacy":
            item.add_argument("--decoder", type=Path, default=Path(__file__).resolve().parent / "build/DecodeLegacy.exe")
    args = parser.parse_args()
    def validate_plan(value, *, verify_sources=False):
        if value.get("schema") == "uc.capture-plan.v2":
            compiled = compile_probe_pair(value, verify_sources=verify_sources)
            return {"plan_hash": compiled.plan_hash, "physical_sites": len(compiled.sites),
                    "logical_subscriptions": sum(len(site.subscriptions) for site in compiled.sites),
                    "runtime_activation_supported": True, "game_runtime_verified": False}
        return validate(value, verify_sources=verify_sources)
    if args.cmd == "select-plan":
        plan = json.loads(args.plan.read_text(encoding="utf-8-sig"))
        result = validate_plan(plan, verify_sources=True)
        with args.destination.open("xb") as stream:
            stream.write(canonical(plan))
        result.update(destination=str(args.destination), game_started=False, xxmi_changed=False)
    elif args.cmd == "validate":
        plan = json.loads(args.plan.read_text(encoding="utf-8-sig"))
        result = validate_plan(plan, verify_sources=args.verify_sources)
        if args.pid:
            result["native_preparation"] = request(args.pid, "validate", plan=plan)
    elif args.cmd == "inspect":
        result = inspect_session(args.directory)
    elif args.cmd in ("index", "import-legacy"):
        index = EvidenceIndex(args.db)
        try:
            result = index.import_session(args.source) if args.cmd == "index" else index.import_legacy(args.source)
        finally:
            index.close()
    elif args.cmd == "query":
        db = sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        result = [dict(row) for row in db.execute(args.sql)]
        db.close()
    elif args.cmd == "export-trace":
        result = export_trace(args.directory, args.destination)
    elif args.cmd == "export-graph":
        result = execution_graph(args.directory, args.destination)
    elif args.cmd == "export-legacy":
        result = legacy_projection(args.directory, args.destination, args.decoder)
    else:
        fields = {}
        if args.cmd == "apply":
            fields["plan"] = json.loads(args.plan.read_text(encoding="utf-8-sig"))
            validate_plan(fields["plan"], verify_sources=True)
        if args.cmd == "mark":
            fields["label"] = args.label
        if args.cmd == "qualify-sites":
            qualification = json.loads(args.qualification.read_text(encoding="utf-8-sig"))
            validate_site_qualification(qualification)
            fields["qualification"] = qualification
        fields = dict(fields)
        if args.cmd == "stop" and args.force:
            fields["force"] = True
        result = request(args.pid, args.cmd, request_id=args.request_id, **fields)
        if args.cmd == "qualify-sites":
            envelope = {"schema": "uc.target-site-qualification-evidence.v1",
                        "request": qualification, "response": result}
            with args.out.open("xb") as stream:
                stream.write(canonical(envelope))
            result["evidence_file"] = str(args.out.resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if isinstance(result, dict) and result.get("ok") is False:
        raise SystemExit(1)

if __name__ == "__main__":
    run_main(main)
