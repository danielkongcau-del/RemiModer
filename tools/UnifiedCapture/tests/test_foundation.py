from __future__ import annotations
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from uc.model import canonical, digest, resolve, validate
from uc.store import (EvidenceWriter, append_manifest, crc32c, decode_chunk, encode_chunk,
                      inspect_session, read_manifest)
from uc.index import EvidenceIndex

def plan():
    return {"schema": "uc.capture-plan.v1", "plan_id": "fixture", "plan_revision": 17,
            "modules": {"fixture": {"image": "FixtureHost.exe", "sha256": "1" * 64}},
            "sources": {"fixture": {"path": "synthetic-test-only", "sha256": "2" * 64}},
            "resources": {"slots_per_point": 8, "max_record_bytes": 4096},
            "points": [{"id": "call", "module": "fixture", "rva": 128, "backend": "gum_attach",
                        "expected_prefix": "90", "evidence": ["fixture"], "reads": [
                            {"id": "field", "base": "rcx", "offset": 8, "op": "scalar", "width": 8,
                             "evidence": ["fixture"]}]}]}

def event(identity, qpc, kind="enter"):
    return {"event_id": identity, "qpc": qpc, "kind": kind, "tid": 1, "point": "call", "generation": 1,
            "invocation_id": identity, "observed_parent": 0}

class PlanTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate(plan())["points"], 1)

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
            lambda p: p["points"][0].update(backend="gum_probe"),
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
        self.temp.cleanup()

    def test_crc32c_known_vector(self):
        self.assertEqual(crc32c(b"123456789"), 0xe3069283)

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

if __name__ == "__main__":
    unittest.main()
