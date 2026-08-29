"""Versioned local evidence store. Indices are never the original evidence."""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import uuid
from .model import canonical

MAGIC = b"UCCHNK01"
PREFIX = struct.Struct("<8sIQ")
RECORD = struct.Struct("<II")

def _crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        table.append(value)
    return tuple(table)

CRC_TABLE = _crc_table()

def crc32c(data: bytes) -> int:
    value = 0xffffffff
    for byte in data:
        value = (value >> 8) ^ CRC_TABLE[(value ^ byte) & 255]
    return value ^ 0xffffffff

def _xpress(data: bytes, expected=None) -> bytes:
    if os.name != "nt":
        raise ValueError("xpress_huff requires Windows cabinet.dll; raw codec is portable")
    dll = ctypes.WinDLL("cabinet", use_last_error=True)
    handle = ctypes.c_void_p()
    create = dll.CreateCompressor if expected is None else dll.CreateDecompressor
    action = dll.Compress if expected is None else dll.Decompress
    close = dll.CloseCompressor if expected is None else dll.CloseDecompressor
    create.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    action.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    close.argtypes = [ctypes.c_void_p]
    if not create(4, None, ctypes.byref(handle)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = ctypes.c_size_t()
        if expected is None:
            if not action(handle, data, len(data), None, 0, ctypes.byref(size)) and ctypes.get_last_error() != 122:
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            size.value = expected
        buffer = ctypes.create_string_buffer(size.value)
        if not action(handle, data, len(data), buffer, len(buffer), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw[:size.value]
    finally:
        close(handle)

def pack_records(records):
    output = bytearray()
    for event, blob in records:
        metadata = canonical(event)
        output += RECORD.pack(len(metadata), len(blob)) + metadata + blob
    return bytes(output)

def unpack_records(payload):
    offset = 0
    while offset < len(payload):
        start = offset
        if len(payload) - offset < RECORD.size:
            raise ValueError("truncated record header")
        meta_size, blob_size = RECORD.unpack_from(payload, offset)
        offset += RECORD.size
        end = offset + meta_size + blob_size
        if end > len(payload):
            raise ValueError("truncated record payload")
        event = json.loads(payload[offset:offset + meta_size])
        if not isinstance(event, dict):
            raise ValueError("event metadata must be an object")
        yield start, end - start, event, payload[offset + meta_size:end]
        offset = end

def encode_chunk(session_id, chunk_id, records, compression="none"):
    records = list(records)
    if not records:
        raise ValueError("empty chunks are not evidence")
    raw = pack_records(records)
    data = _xpress(raw) if compression == "xpress_huff" else raw
    if compression not in ("none", "xpress_huff"):
        raise ValueError("unknown codec")
    if len(data) >= len(raw):
        compression, data = "none", raw
    ids = [event["event_id"] for event, _ in records]
    clocks = [event["qpc"] for event, _ in records]
    header = {"format_version": 1, "record_encoding": "uc.record.v1", "session_id": session_id,
              "chunk_id": chunk_id, "min_event_id": min(ids), "max_event_id": max(ids),
              "min_qpc": min(clocks), "max_qpc": max(clocks), "event_count": len(records),
              "uncompressed_size": len(raw), "compressed_size": len(data), "compression_type": compression}
    header["sha256"] = hashlib.sha256(canonical(header) + data).hexdigest()
    header["crc32c"] = crc32c(data)
    encoded = canonical(header)
    return PREFIX.pack(MAGIC, len(encoded), len(data)) + encoded + data, header

def decode_chunk(data, *, max_uncompressed=1024 * 1024 * 1024):
    if len(data) < PREFIX.size:
        raise ValueError("truncated chunk prefix")
    magic, header_size, payload_size = PREFIX.unpack_from(data)
    if magic != MAGIC or header_size > 1024 * 1024:
        raise ValueError("invalid chunk prefix")
    if PREFIX.size + header_size + payload_size != len(data):
        raise ValueError("chunk length mismatch")
    header = json.loads(data[PREFIX.size:PREFIX.size + header_size])
    payload = data[PREFIX.size + header_size:]
    unsigned = {key: value for key, value in header.items() if key not in ("crc32c", "sha256")}
    if header["format_version"] != 1 or header["record_encoding"] != "uc.record.v1":
        raise ValueError("unsupported evidence format")
    if header["compressed_size"] != len(payload) or header["uncompressed_size"] > max_uncompressed:
        raise ValueError("invalid payload lengths")
    if crc32c(payload) != header["crc32c"]:
        raise ValueError("chunk CRC32C mismatch")
    if hashlib.sha256(canonical(unsigned) + payload).hexdigest() != header["sha256"]:
        raise ValueError("chunk SHA-256 mismatch")
    codec = header["compression_type"]
    if codec == "xpress_huff":
        payload = _xpress(payload, header["uncompressed_size"])
    elif codec != "none":
        raise ValueError("unsupported codec")
    if len(payload) != header["uncompressed_size"]:
        raise ValueError("decompressed length mismatch")
    events = list(unpack_records(payload))
    if len(events) != header["event_count"]:
        raise ValueError("event count mismatch")
    if not events:
        raise ValueError("empty chunk")
    ids = [item[2]["event_id"] for item in events]
    clocks = [item[2]["qpc"] for item in events]
    if (min(ids), max(ids), min(clocks), max(clocks)) != (
        header["min_event_id"], header["max_event_id"], header["min_qpc"], header["max_qpc"]):
        raise ValueError("chunk range mismatch")
    return header, events

def append_manifest(path: Path, record: dict):
    raw = canonical(record)
    envelope = canonical({"record": record, "sha256": hashlib.sha256(raw).hexdigest()}) + b"\n"
    with path.open("ab") as stream:
        stream.write(envelope)
        stream.flush()
        os.fsync(stream.fileno())

def read_manifest(path: Path):
    records, errors = [], []
    if not path.exists():
        return [], ["manifest_missing"]
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            try:
                if not line.endswith(b"\n"):
                    raise ValueError("uncommitted manifest tail")
                envelope = json.loads(line)
                record = envelope["record"]
                if hashlib.sha256(canonical(record)).hexdigest() != envelope["sha256"]:
                    raise ValueError("manifest checksum")
                records.append(record)
            except (ValueError, KeyError, TypeError) as error:
                errors.append(f"manifest:{number}:{error}")
                break
    return records, errors

class EvidenceWriter:
    def __init__(self, directory: Path, session_id=None):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.session_id = session_id or str(uuid.uuid4())
        self.chunk_id, self.closed = 0, False
        self.manifest = self.directory / "session.manifest"
        append_manifest(self.manifest, {"kind": "session", "session_id": self.session_id,
                                      "schema": "uc.session.v1", "automatic_stop": False})

    def write(self, records, compression="none"):
        if self.closed:
            raise ValueError("sealed session")
        encoded, header = encode_chunk(self.session_id, self.chunk_id, records, compression)
        name = f"chunk-{self.chunk_id:08d}.ucb"
        pending, final = self.directory / (name + ".partial"), self.directory / name
        with pending.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if final.exists():
            raise FileExistsError(final)
        pending.rename(final)
        append_manifest(self.manifest, {"kind": "chunk", "file": name, **header})
        self.chunk_id += 1
        return final

    def close(self, *, cleanup="STOPPED_CLEAN", loss=None):
        if self.closed:
            return
        append_manifest(self.manifest, {"kind": "session_end", "session_id": self.session_id,
                                      "cleanup": cleanup, "loss": loss or [], "chunks": self.chunk_id})
        self.closed = True

def inspect_session(directory: Path):
    directory = Path(directory)
    records, errors = read_manifest(directory / "session.manifest")
    declared = {record["file"]: record for record in records if record.get("kind") == "chunk"}
    sessions = [record["session_id"] for record in records if record.get("kind") == "session"]
    valid, seen = [], set()
    for path in sorted(directory.glob("chunk-*.ucb")):
        try:
            header, events = decode_chunk(path.read_bytes())
            if sessions != [header["session_id"]]:
                raise ValueError("session identity mismatch")
            if path.name not in declared:
                errors.append(f"orphan_sealed_chunk:{path.name}")
            elif any(declared[path.name].get(key) != value for key, value in header.items()):
                raise ValueError("manifest/chunk mismatch")
            for _, _, event, _ in events:
                if event["event_id"] in seen:
                    raise ValueError("duplicate event id")
                seen.add(event["event_id"])
            valid.append({"file": path.name, **header})
        except (ValueError, KeyError, OSError) as error:
            errors.append(f"{path.name}:{error}")
    for name in declared:
        if not (directory / name).is_file():
            errors.append(f"missing_chunk:{name}")
    errors.extend(f"unsealed_tail:{path.name}" for path in directory.glob("*.partial"))
    ended = records[-1] if records and records[-1].get("kind") == "session_end" else None
    if ended is None:
        errors.append("session_tail_unknown")
    elif ended.get("chunks") != len(declared):
        errors.append("final_chunk_count_mismatch")
    return {"schema": "uc.store-inspection.v1", "chunks": valid, "errors": errors,
            "storage_complete": not errors, "cleanup": ended.get("cleanup") if ended else None,
            "loss": ended.get("loss") if ended else None,
            "semantic_completeness": "NOT_ESTABLISHED_BY_FILE_HASHES"}
