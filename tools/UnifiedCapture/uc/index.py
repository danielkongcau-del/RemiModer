"""Rebuildable, provenance-preserving indices. No inferred gameplay edges."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sqlite3
from .model import canonical, file_hash
from .store import decode_chunk_file, event_dictionary_context, inspect_session, read_manifest

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS artifacts(
 id TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL, kind TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
 id TEXT PRIMARY KEY, directory TEXT, inspection TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
 source TEXT NOT NULL REFERENCES artifacts(id), session TEXT NOT NULL, event_id TEXT NOT NULL,
 offset INTEGER NOT NULL, length INTEGER NOT NULL, offset_domain TEXT NOT NULL,
 kind TEXT, qpc TEXT, tid TEXT, point TEXT, generation TEXT, invocation TEXT,
 observed_parent TEXT, reads TEXT, metadata TEXT NOT NULL, PRIMARY KEY(source,offset));
CREATE INDEX IF NOT EXISTS event_call ON events(session,invocation);
CREATE INDEX IF NOT EXISTS event_point ON events(session,point,generation,qpc);
CREATE TABLE IF NOT EXISTS evidence_refs(
 id TEXT PRIMARY KEY, source TEXT NOT NULL REFERENCES artifacts(id), offset INTEGER NOT NULL,
 length INTEGER NOT NULL, offset_domain TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS addresses(
 id INTEGER PRIMARY KEY, session TEXT NOT NULL, address TEXT NOT NULL,
 evidence TEXT NOT NULL REFERENCES evidence_refs(id));
CREATE TABLE IF NOT EXISTS candidates(
 id INTEGER PRIMARY KEY, observed_address INTEGER NOT NULL REFERENCES addresses(id),
 lifetime TEXT NOT NULL CHECK(lifetime='UNKNOWN'));
CREATE TABLE IF NOT EXISTS instances(
 id TEXT PRIMARY KEY, candidate INTEGER REFERENCES candidates(id),
 evidence TEXT NOT NULL REFERENCES evidence_refs(id),
 proof_kind TEXT NOT NULL CHECK(proof_kind IN ('native_creation','native_generation','native_lifetime_binding')),
 end_evidence TEXT REFERENCES evidence_refs(id));
CREATE TABLE IF NOT EXISTS entity_bindings(
 instance TEXT NOT NULL REFERENCES instances(id), entity_namespace TEXT NOT NULL, entity_key TEXT NOT NULL,
 evidence TEXT NOT NULL REFERENCES evidence_refs(id), PRIMARY KEY(instance,entity_namespace,entity_key,evidence));
CREATE TABLE IF NOT EXISTS causal_edges(
 parent TEXT NOT NULL REFERENCES evidence_refs(id), child TEXT NOT NULL REFERENCES evidence_refs(id),
 proof TEXT NOT NULL REFERENCES evidence_refs(id),
 kind TEXT NOT NULL CHECK(kind IN ('observed_nesting','native_job','native_queue','native_callsite')),
 PRIMARY KEY(parent,child,proof,kind));
CREATE TABLE IF NOT EXISTS checkpoints(session TEXT NOT NULL, ordinal INTEGER NOT NULL,
 record TEXT NOT NULL, PRIMARY KEY(session,ordinal));
"""

class EvidenceIndex:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(events)")}
        if "reads" not in columns:
            self.db.execute("ALTER TABLE events ADD COLUMN reads TEXT")

    def close(self):
        self.db.commit()
        self.db.close()

    def artifact(self, path, kind):
        path = Path(path).resolve()
        digest = file_hash(path)
        identity = hashlib.sha256((str(path) + "\0" + digest).encode()).hexdigest()
        self.db.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?)", (identity, str(path), digest, kind))
        return identity

    def add_event(self, artifact, session, offset, length, domain, event):
        event_id = str(event.get("event_id", event.get("sequence", offset)))
        small = {key: event.get(key) for key in (
            "kind", "event", "point", "generation", "invocation_id", "callId", "tid", "qpc",
            "beginQpc", "endQpc", "observed_parent", "parent_known", "parent", "phase", "read_failures", "truncated") if key in event}
        small["full_event_is_at_source"] = True
        # Read results travel with the index row so argument/object queries do
        # not force a re-decode of every chunk.
        reads = event.get("reads")
        self.db.execute("""INSERT OR IGNORE INTO events(
            source,session,event_id,offset,length,offset_domain,kind,qpc,tid,point,
            generation,invocation,observed_parent,reads,metadata)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            artifact, session, event_id, offset, length, domain, event.get("kind", event.get("event")),
            str(event.get("qpc", event.get("beginQpc", ""))), str(event.get("tid", "")),
            event.get("point"), str(event.get("generation", "")),
            str(event.get("invocation_id", event.get("callId", ""))),
            str(event.get("observed_parent", event.get("parent", ""))),
            canonical(reads).decode() if reads is not None else None, canonical(small).decode()))
        evidence_id = f"{artifact}:{offset}:{length}"
        self.db.execute("INSERT OR IGNORE INTO evidence_refs VALUES(?,?,?,?,?)",
                        (evidence_id, artifact, offset, length, domain))
        return evidence_id

    def import_session(self, directory):
        directory = Path(directory).resolve()
        inspection = inspect_session(directory)
        records, _ = read_manifest(directory / "session.manifest")
        dictionary_context = event_dictionary_context(directory / "session.manifest", records)
        header = next((r for r in records if r.get("kind") == "session"), None)
        if header is None:
            raise ValueError("no valid session identity")
        session = header["session_id"]
        self.db.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?)",
                        (session, str(directory), canonical(inspection).decode()))
        for ordinal, record in enumerate(records):
            self.db.execute("INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)",
                            (session, ordinal, canonical(record).decode()))
        count = 0
        for chunk in inspection["chunks"]:
            path = directory / chunk["file"]
            artifact = self.artifact(path, "uc.chunk.v1")
            _, events = decode_chunk_file(path, dictionary_context=dictionary_context)
            for offset, length, event, _ in events:
                self.add_event(artifact, session, offset, length, "decompressed_payload", event)
                count += 1
        self.db.commit()
        return {"events": count, "session": session, "inspection": inspection}

    def import_legacy(self, path):
        """Stream complete JSONL, retain original bytes; malformed lines are not erased."""
        path = Path(path).resolve()
        artifact = self.artifact(path, "legacy.jsonl")
        session = "legacy:" + artifact
        count, failures, header, tail = 0, [], None, None
        with path.open("rb") as stream:
            while True:
                offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("non-object legacy record")
                    if header is None:
                        header = event
                    tail = event
                    self.add_event(artifact, session, offset, len(line), "original_file", event)
                    count += 1
                    if count % 5000 == 0:
                        self.db.commit()
                except (ValueError, TypeError) as error:
                    failures.append({"offset": offset, "length": len(line), "error": str(error)})
        report = {"events": count, "malformed": failures, "header": header, "tail": tail,
                  "semantic_completeness": "UNKNOWN", "stream_completeness": "requires_legacy_analyzer"}
        # Do not serialize a giant final snapshot into the index inspection.
        report["header"] = {k: v for k, v in (header or {}).items() if k in ("schema", "event", "pid", "build", "qpcFrequency")}
        report["tail"] = {k: v for k, v in (tail or {}).items() if k in ("event", "restored", "dropped", "activeCalls", "produced", "ioErrorBeforeStop")}
        self.db.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?)", (session, str(path), canonical(report).decode()))
        self.db.commit()
        return {"artifact": artifact, **report}

    def candidate(self, session, address, evidence):
        address_id = self.db.execute("INSERT INTO addresses(session,address,evidence) VALUES(?,?,?)",
                                     (session, address, evidence)).lastrowid
        return self.db.execute("INSERT INTO candidates(observed_address,lifetime) VALUES(?,'UNKNOWN')",
                               (address_id,)).lastrowid

    def instance(self, identity, candidate, evidence, proof_kind):
        self.db.execute("INSERT INTO instances(id,candidate,evidence,proof_kind) VALUES(?,?,?,?)",
                        (identity, candidate, evidence, proof_kind))

    def absence(self, session, point, begin, end):
        """Conservative bounded observation answer; never returns NOT_EXECUTED."""
        row = self.db.execute("SELECT inspection FROM sessions WHERE id=?", (session,)).fetchone()
        if not row or begin > end:
            return {"result": "UNKNOWN", "reason": "unknown_session_or_window"}
        inspection = json.loads(row[0])
        if not inspection.get("storage_complete") or inspection.get("cleanup") != "STOPPED_CLEAN":
            return {"result": "UNKNOWN", "reason": "incomplete_session"}
        records = [json.loads(row[0]) for row in self.db.execute(
            "SELECT record FROM checkpoints WHERE session=? ORDER BY ordinal", (session,))]
        windows = [r for r in records if r.get("kind") == "coverage" and r.get("point") == point]
        if not any(r.get("complete") is True and r["begin_qpc"] <= begin and r["end_qpc"] >= end for r in windows):
            return {"result": "UNKNOWN", "reason": "coverage_not_proven"}
        for loss in inspection.get("loss") or []:
            if loss.get("point") in (None, point) and any(loss.get(k, 0) for k in ("events", "read_failures", "truncated")):
                if loss.get("first_qpc", 0) <= end and loss.get("last_qpc", (1 << 64) - 1) >= begin:
                    return {"result": "UNKNOWN", "reason": "loss_or_invalid_reads"}
        # QPCs are TEXT to preserve uint64; filter integers in Python.
        for (clock,) in self.db.execute("SELECT qpc FROM events WHERE session=? AND point=? AND kind IN ('enter','probe')", (session, point)):
            if clock and begin <= int(clock) <= end:
                return {"result": "OBSERVED"}
        return {"result": "NOT_OBSERVED_IN_COVERED_WINDOW", "behavior_not_executed": "NOT_PROVEN"}
