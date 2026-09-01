from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from uc.model import canonical, digest, resolve, validate
from uc.store import (EvidenceWriter, append_manifest, crc32c, decode_chunk, encode_chunk,
                      decode_chunk_file, inspect_session, read_manifest)
import uc.store as store_module
from uc.index import EvidenceIndex
from d0_analyze import _load_finish
from d0ctl import save_finish_attempt

def plan():
    return {"schema": "uc.capture-plan.v1", "plan_id": "fixture", "plan_revision": 17,
            "modules": {"fixture": {"image": "FixtureHost.exe", "sha256": "1" * 64}},
            "sources": {"fixture": {"path": "synthetic-test-only", "sha256": "2" * 64}},
            "resources": {"slots_per_point": 8, "max_record_bytes": 4096},
            "points": [{"id": "call", "module": "fixture", "rva": 128, "backend": "gum_probe",
                        "expected_prefix": "90", "evidence": ["fixture"], "reads": [
                            {"id": "field", "base": "rcx", "offset": 8, "op": "scalar", "width": 8, "phase": "enter",
                             "evidence": ["fixture"]}]}]}

def event(identity, qpc, kind="enter"):
    return {"event_id": identity, "qpc": qpc, "kind": kind, "tid": 1, "point": "call", "generation": 1,
            "invocation_id": identity, "observed_parent": 0}

class PlanTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate(plan())["points"], 1)

    def test_v2_schema_accepts_register_base(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is an optional schema-test dependency")
        schema = json.loads((ROOT / "schemas/capture-plan-v2.schema.json").read_text(encoding="utf-8"))
        base_schema = schema["properties"]["observations"]["items"]["properties"]["entry"]["properties"]["reads"]["items"]["properties"]["base"]
        jsonschema.Draft202012Validator(base_schema).validate("rcx")

    def test_canonical_key_order(self):
        p = plan()
        self.assertEqual(digest(p), digest(dict(reversed(list(p.items())))))

    def test_generation_rollback(self):
        p = plan()
        modules = {"fixture": {"base": 0x1000, "size": 4096, "sha256": "1" * 64, "load_identity": "load-1"}}
        first = resolve(p, modules, 42, "one")
        p["plan_revision"] = 18
        second = resolve(p, modules, 43, "one")
        p["plan_revision"] = 17
        third = resolve(p, modules, 44, "one")
        self.assertEqual(first.plan_hash, third.plan_hash)
        self.assertNotEqual(first.generation, third.generation)
        self.assertEqual(second.plan_revision, 18)
        self.assertEqual(first.bindings[0][1], 0x1080)
        with self.assertRaises(Exception):
            first.generation = 99

    def test_waiting_module(self):
        with self.assertRaisesRegex(LookupError, "WAITING_MODULE"):
            resolve(plan(), {}, 1, "one")

    def test_wrong_module(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            resolve(plan(), {"fixture": {"sha256": "0" * 64}}, 1, "one")

    def test_source_hash(self):
        p = plan()
        with self.assertRaises(OSError):
            validate(p, verify_sources=True)

    def test_invalid_plans(self):
        mutations = [
            lambda p: p.update(schema="wrong"),
            lambda p: p.update(plan_revision=-1),
            lambda p: p.update(plan_revision=True),
            lambda p: p["resources"].update(slots_per_point=0),
            lambda p: p["resources"].update(max_record_bytes=1),
            lambda p: p["points"].append(copy.deepcopy(p["points"][0])),
            lambda p: p["points"][0].update(backend="replace"),
            lambda p: p["points"][0].update(evidence=[]),
            lambda p: p["points"][0].update(expected_prefix="zz"),
            lambda p: p["points"][0]["reads"][0].update(base="later"),
            lambda p: p["points"][0]["reads"][0].update(base="arg0"),
            lambda p: p["points"][0]["reads"][0].update(width=3),
            lambda p: p["points"][0]["reads"][0].update(evidence=[]),
            lambda p: p["points"][0].update(backend="gum_attach"),
            lambda p: p["points"][0].update(backend="slot"),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(case=number):
                p = plan()
                mutate(p)
                with self.assertRaises((ValueError, KeyError)):
                    validate(p)

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="uc-foundation-")
        self.path = Path(self.temp.name)

    def tearDown(self):
        store_module._DECODE_CACHE.clear()
        store_module._DECODE_CACHE_BYTES = 0
        self.temp.cleanup()

    def test_crc32c_known_vector(self):
        self.assertEqual(crc32c(b"123456789"), 0xe3069283)

    def test_crc32c_slicing_on_long_input(self):
        # Exercise multiple 8-byte slices plus a remainder, against the same
        # known-answer construction as the reference byte loop.
        payload = bytes(range(256)) * 5 + b"tail"
        reference = 0xffffffff
        table = []
        for value in range(256):
            for _ in range(8):
                value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
            table.append(value)
        for byte in payload:
            reference = (reference >> 8) ^ table[(reference ^ byte) & 255]
        self.assertEqual(crc32c(payload), reference ^ 0xffffffff)

    def test_manifest_chain_detects_deletion_and_reordering(self):
        writer = EvidenceWriter(self.path / "session", "chain")
        writer.write([(event(1, 1), b"abc")])
        append_manifest(writer.manifest, {"kind": "user_mark", "label": "mid", "qpc": 5})
        writer.close()
        lines = writer.manifest.read_bytes().splitlines(keepends=True)
        # Deleting a middle line breaks the prev_sha256 linkage.
        deleted = b"".join(lines[:1] + lines[2:])
        other = self.path / "deleted.manifest"
        other.write_bytes(deleted)
        _, errors = read_manifest(other)
        self.assertTrue(any("chain" in error for error in errors), errors)
        # Swapping two sealed lines also breaks the chain.
        swapped = self.path / "swapped.manifest"
        swapped.write_bytes(b"".join(lines[1:2] + lines[0:1] + lines[2:]))
        _, errors = read_manifest(swapped)
        self.assertTrue(any("chain" in error for error in errors), errors)

    def test_manifest_chain_can_follow_verified_legacy_lines(self):
        path = self.path / "legacy.manifest"
        records = [{"kind": "session", "session_id": "legacy"}, {"kind": "user_mark", "qpc": 1}]
        with path.open("wb") as stream:
            for record in records:
                stream.write(canonical({"record": record, "sha256": hashlib.sha256(canonical(record)).hexdigest()}) + b"\n")
        append_manifest(path, {"kind": "session_end", "session_id": "legacy"})
        decoded, errors = read_manifest(path)
        self.assertFalse(errors, errors)
        self.assertEqual([row["kind"] for row in decoded], ["session", "user_mark", "session_end"])

    def test_decode_cache_enforces_total_weight(self):
        old_limit = store_module._DECODE_CACHE_MAX_BYTES
        try:
            store_module._DECODE_CACHE_MAX_BYTES = 900
            for identity in (1, 2):
                encoded, _ = encode_chunk("cache", identity, [(event(identity, identity), bytes(512))])
                path = self.path / f"cache-{identity}.ucb"
                path.write_bytes(encoded)
                decode_chunk_file(path)
            self.assertLessEqual(store_module._DECODE_CACHE_BYTES, store_module._DECODE_CACHE_MAX_BYTES)
            self.assertLessEqual(len(store_module._DECODE_CACHE), 1)
        finally:
            store_module._DECODE_CACHE_MAX_BYTES = old_limit

    def test_plan_accepts_entry_predicate_and_string_reads(self):
        p = plan()
        p["points"][0]["reads"] = [
            {"id": "kind", "base": "rcx", "op": "scalar", "width": 8, "phase": "enter",
             "when": {"op": "eq", "value": 7, "mask": 255}, "evidence": ["fixture"]},
            {"id": "name", "base": "rdx", "op": "string", "max_bytes": 64, "phase": "enter",
             "evidence": ["fixture"]},
            {"id": "count", "base": "r8", "op": "scalar", "width": 4, "phase": "enter",
             "evidence": ["fixture"]},
            {"id": "items", "base": "r9", "op": "array", "count_from": "count", "stride": 4,
             "max_count": 8, "phase": "enter", "evidence": ["fixture"]},
        ]
        self.assertEqual(validate(p)["points"], 1)
        # Predicates are enter-phase only and scalar-only.
        for mutate in (lambda r: r.update(phase="leave"),
                       lambda r: r.update(op="block", size=8),
                       lambda r: r["when"].update(op="lt")):
            with self.subTest(mutate=mutate):
                broken = plan()
                broken["points"][0]["reads"] = copy.deepcopy(p["points"][0]["reads"])
                mutate(broken["points"][0]["reads"][0])
                with self.assertRaises(ValueError):
                    validate(broken)

    def test_binary_roundtrip(self):
        raw = bytes(range(256)) + b"\x00\x00\xc0\x7f"  # NaN bits, not a JSON float
        encoded, _ = encode_chunk("one", 0, [(event(9, 99), raw), (event(1, 3), b"")])
        header, records = decode_chunk(encoded)
        self.assertEqual((header["min_event_id"], header["max_event_id"]), (1, 9))
        self.assertEqual((header["min_qpc"], header["max_qpc"]), (3, 99))
        self.assertEqual(records[0][3], raw)

    def test_compression_roundtrip(self):
        encoded, header = encode_chunk("one", 0, [(event(1, 1), b"abcdef" * 1000)], "xpress_huff")
        self.assertEqual(header["compression_type"], "xpress_huff")
        self.assertEqual(decode_chunk(encoded)[1][0][3], b"abcdef" * 1000)

    def test_corruption_and_truncation(self):
        encoded, _ = encode_chunk("one", 0, [(event(1, 1), b"abc")])
        for data in (encoded[:4], encoded[:-1], encoded + b"x", encoded[:-1] + b"z"):
            with self.subTest(length=len(data)):
                with self.assertRaises(ValueError):
                    decode_chunk(data)

    def test_seal_and_preserve(self):
        writer = EvidenceWriter(self.path / "session")
        source = writer.write([(event(1, 1), b"abc")])
        before = source.read_bytes()
        writer.close()
        self.assertTrue(inspect_session(writer.directory)["storage_complete"])
        self.assertEqual(source.read_bytes(), before)
        with self.assertRaises(ValueError):
            writer.write([(event(2, 2), b"")])
        with self.assertRaises(FileExistsError):
            EvidenceWriter(writer.directory)

    def test_crash_tail(self):
        writer = EvidenceWriter(self.path / "session")
        writer.write([(event(1, 1), b"abc")])
        with (writer.directory / "chunk-00000001.ucb.partial").open("xb") as stream:
            stream.write(b"partial")
        report = inspect_session(writer.directory)
        self.assertFalse(report["storage_complete"])
        self.assertIn("session_tail_unknown", report["errors"])
        self.assertEqual(len(report["chunks"]), 1)

    def test_manifest_torn_tail(self):
        writer = EvidenceWriter(self.path / "session")
        with writer.manifest.open("ab") as stream:
            stream.write(b'{"unfinished":')
        records, errors = read_manifest(writer.manifest)
        self.assertEqual(len(records), 1)
        self.assertTrue(errors)

    def test_orphan_chunk(self):
        writer = EvidenceWriter(self.path / "session")
        encoded, _ = encode_chunk(writer.session_id, 0, [(event(1, 1), b"abc")])
        (writer.directory / "chunk-00000000.ucb").write_bytes(encoded)
        report = inspect_session(writer.directory)
        self.assertIn("orphan_sealed_chunk:chunk-00000000.ucb", report["errors"])

    def test_index_rebuild_and_identity(self):
        writer = EvidenceWriter(self.path / "session", "one")
        writer.write([(event(1, 1), b"abc")])
        writer.close()
        idx = EvidenceIndex(self.path / "index.db")
        idx.import_session(writer.directory)
        idx.import_session(writer.directory)
        self.assertEqual(idx.db.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        ref = idx.db.execute("SELECT id FROM evidence_refs").fetchone()[0]
        a, b = idx.candidate("one", "0x1234", ref), idx.candidate("one", "0x1234", ref)
        self.assertNotEqual(a, b)
        with self.assertRaises(sqlite3.IntegrityError):
            idx.instance("guess", a, ref, "same_vtable")
        idx.instance("native-1", a, ref, "native_creation")
        self.assertIsNone(idx.db.execute("SELECT end_evidence FROM instances").fetchone()[0])
        with self.assertRaises(sqlite3.IntegrityError):
            idx.db.execute("INSERT INTO causal_edges VALUES(?,?,?,?)", (ref, ref, ref, "nearby_time"))
        idx.close()

    def test_index_reuses_one_dictionary_context_for_all_chunks(self):
        writer = EvidenceWriter(self.path / "session", "one")
        writer.write([(event(1, 1), b"abc")])
        writer.write([(event(2, 2), b"def")])
        writer.close()
        idx = EvidenceIndex(self.path / "index.db")
        from uc import index as index_module
        original = index_module.decode_chunk_file
        contexts = []

        def observe_context(path, *, dictionary_context=None):
            contexts.append(dictionary_context)
            return original(path, dictionary_context=dictionary_context)

        with mock.patch.object(index_module, "decode_chunk_file", side_effect=observe_context):
            idx.import_session(writer.directory)
        self.assertEqual(len(contexts), 2)
        self.assertIsNotNone(contexts[0])
        self.assertIs(contexts[0], contexts[1])
        idx.close()

    def test_index_migrates_pre_reads_schema(self):
        path = self.path / "old-index.db"
        db = sqlite3.connect(path)
        db.execute("""CREATE TABLE events(
            source TEXT NOT NULL, session TEXT NOT NULL, event_id TEXT NOT NULL,
            offset INTEGER NOT NULL, length INTEGER NOT NULL, offset_domain TEXT NOT NULL,
            kind TEXT, qpc TEXT, tid TEXT, point TEXT, generation TEXT, invocation TEXT,
            observed_parent TEXT, metadata TEXT NOT NULL, PRIMARY KEY(source,offset))""")
        db.commit();db.close()
        idx = EvidenceIndex(path)
        columns = {row[1] for row in idx.db.execute("PRAGMA table_info(events)")}
        self.assertIn("reads", columns)
        idx.close()

    def test_absence_requires_coverage(self):
        writer = EvidenceWriter(self.path / "session", "one")
        writer.write([(event(1, 1), b"")])
        writer.close()
        idx = EvidenceIndex(self.path / "index.db")
        idx.import_session(writer.directory)
        self.assertEqual(idx.absence("one", "call", 10, 20)["result"], "UNKNOWN")
        idx.close()

    def test_absence_and_loss(self):
        for with_loss in (False, True):
            with self.subTest(loss=with_loss):
                writer = EvidenceWriter(self.path / str(with_loss), str(with_loss))
                writer.write([(event(1, 1), b"")])
                append_manifest(writer.manifest, {"kind": "coverage", "point": "call", "begin_qpc": 0,
                                                  "end_qpc": 100, "complete": True})
                loss = [{"point": "call", "events": 3, "first_qpc": 10, "last_qpc": 19}] if with_loss else []
                writer.close(loss=loss)
                idx = EvidenceIndex(self.path / (str(with_loss) + ".db"))
                idx.import_session(writer.directory)
                self.assertEqual(idx.absence(str(with_loss), "call", 10, 20)["result"],
                                 "UNKNOWN" if with_loss else "NOT_OBSERVED_IN_COVERED_WINDOW")
                idx.close()

    def test_legacy_byte_offsets_and_errors_preserved(self):
        path = self.path / "old.jsonl"
        data = b'{"event":"header","pid":42}\n{broken}\n{"event":"enter","callId":1}\n'
        path.write_bytes(data)
        idx = EvidenceIndex(self.path / "legacy.db")
        report = idx.import_legacy(path)
        self.assertEqual(report["events"], 2)
        self.assertEqual(len(report["malformed"]), 1)
        for offset, length in idx.db.execute("SELECT offset,length FROM events"):
            json.loads(data[offset:offset + length])
        self.assertEqual(path.read_bytes(), data)
        idx.close()

    def test_finish_attempts_use_monotonic_immutable_sequence(self):
        legacy = self.path / "finish-attempt-100-old.json"
        legacy.write_bytes(canonical({"state": "OLD"}))
        first = save_finish_attempt(self.path, {"state": "FIRST"})
        second = save_finish_attempt(self.path, {"state": "SECOND"})
        self.assertEqual(int(first.stem.split("-")[2]), 101)
        self.assertEqual(int(second.stem.split("-")[2]), 102)
        self.assertEqual(_load_finish(self.path)["state"], "SECOND")

if __name__ == "__main__":
    unittest.main()
