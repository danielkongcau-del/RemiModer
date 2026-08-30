"""Versioned local evidence store. Indices are never the original evidence."""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import threading
import uuid
from collections import OrderedDict
from .model import canonical, REGISTERS

MAGIC = b"UCCHNK01"
PREFIX = struct.Struct("<8sIQ")
RECORD = struct.Struct("<II")
BINARY_EVENT_V2 = struct.Struct("<8sIIII8Q9I")
BINARY_EVENT_V3 = struct.Struct("<8sIIII9Q10I")
BINARY_READ = struct.Struct("<QQQIII")
BINARY_EVENT_MAGICS = {b"UCEVT002": 2, b"UCEVT003": 3}
BINARY_KINDS = {1: "probe", 2: "enter", 3: "leave",
                4: "frame_absent_after_observed_point", 5: "aggregate_entry_sample"}

def _crc_tables():
    # Slicing-by-8: eight incremental tables so the hot loop consumes a full
    # uint64 per iteration instead of one byte (~3-4x in CPython, no new deps).
    base = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        base.append(value)
    tables = [tuple(base)]
    for _ in range(7):
        prior = tables[-1]
        tables.append(tuple((prior[i] >> 8) ^ base[prior[i] & 255] for i in range(256)))
    return tuple(tables)

CRC_TABLES = _crc_tables()

def crc32c(data: bytes) -> int:
    t0, t1, t2, t3, t4, t5, t6, t7 = CRC_TABLES
    value = 0xffffffff
    length = len(data)
    offset = 0
    while length - offset >= 8:
        word = int.from_bytes(data[offset:offset + 8], "little")
        low = (value ^ word) & 0xffffffff
        high = (word >> 32) & 0xffffffff
        value = (t7[low & 255] ^ t6[(low >> 8) & 255] ^ t5[(low >> 16) & 255] ^ t4[(low >> 24) & 255]
                 ^ t3[high & 255] ^ t2[(high >> 8) & 255] ^ t1[(high >> 16) & 255] ^ t0[(high >> 24) & 255])
        offset += 8
    for byte in data[offset:]:
        value = (value >> 8) ^ t0[(value ^ byte) & 255]
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

def _binary_event(metadata: bytes, dictionaries):
    if len(metadata) < BINARY_EVENT_V2.size:
        raise ValueError("truncated binary event")
    magic = metadata[:8]
    format_version = BINARY_EVENT_MAGICS.get(magic)
    if format_version is None:
        raise ValueError("unsupported binary event metadata")
    binary = BINARY_EVENT_V3 if format_version == 3 else BINARY_EVENT_V2
    if len(metadata) < binary.size:
        raise ValueError("truncated binary event")
    values = binary.unpack_from(metadata)
    magic, version, kind_code, point_numeric_id, tid = values[:5]
    if version != format_version or kind_code not in BINARY_KINDS:
        raise ValueError("unsupported binary event metadata")
    if format_version == 3:
        (event_id, generation, qpc, read_end_qpc, invocation, parent, retention_hash,
         _stack_marker, retention_entry_return) = values[5:14]
        (flags, register_mask, xmm_mask, argument_mask, exit_hook_id, legacy_offset,
         legacy_size, legacy_failures, read_count, retention_part_count) = values[14:24]
    else:
        (event_id, generation, qpc, read_end_qpc, invocation, parent, retention_hash,
         _stack_marker) = values[5:13]
        (flags, register_mask, xmm_mask, argument_mask, exit_hook_id, legacy_offset,
         legacy_size, legacy_failures, read_count) = values[13:22]
        retention_entry_return = retention_hash
        retention_part_count = 1 if flags & 32 else 0
    dictionary = (dictionaries or {}).get((generation, point_numeric_id))
    if dictionary is None:
        raise ValueError(f"missing event dictionary: generation={generation} point={point_numeric_id}")
    read_ids = dictionary.get("reads", [])
    if len(read_ids) != read_count:
        raise ValueError("binary event read dictionary mismatch")
    offset = binary.size

    def take(size):
        nonlocal offset
        if size > len(metadata) - offset:
            raise ValueError("truncated binary event variable fields")
        value = metadata[offset:offset + size]
        offset += size
        return value

    retention_values = [int.from_bytes(take(8), "little")
                        for _ in range(retention_part_count)] if format_version == 3 else \
                       ([retention_hash] if retention_part_count else [])
    registers = {}
    for index, name in enumerate(REGISTERS):
        if register_mask & (1 << index):
            registers[name] = int.from_bytes(take(8), "little")
    arguments = []
    for index in range(8):
        if argument_mask & (1 << index):
            arguments.append({"index": index, "bits": int.from_bytes(take(8), "little")})
    xmm = {}
    for index in range(16):
        if xmm_mask & (1 << index):
            xmm[str(index)] = take(16).hex()
    reads, failures, truncated = [], 0, 0
    for read_id in read_ids:
        if BINARY_READ.size > len(metadata) - offset:
            raise ValueError("truncated binary read result")
        address, value, count, begin, length, status = BINARY_READ.unpack_from(metadata, offset)
        offset += BINARY_READ.size
        reads.append({"id": read_id, "address": address, "value": value, "status": status,
                      "offset": begin, "length": length, "declared_count": count})
        failures += status in (2, 3, 5)
        truncated += status == 4
    if offset != len(metadata):
        raise ValueError("binary event metadata has an unknown tail")
    event = {"schema": "uc.event.v1", "event_id": event_id,
        "kind": BINARY_KINDS[kind_code], "point": dictionary["point"],
        "generation": generation, "qpc": qpc, "read_end_qpc": read_end_qpc,
        "tid": tid, "observed_parent": parent, "parent_known": bool(flags & 1),
        "snapshot_atomic": False, "exceptional": bool(flags & 2), "reads": reads,
        "read_failures": failures, "truncated": truncated,
        "raw_abi": {"registers": registers, "xmm": xmm,
                    "register_mask": register_mask, "xmm_mask": xmm_mask},
        "semantic_interpretation": {
            "version": "uc.legacy-abi.v1" if dictionary["backend"] == "slot" else "uc.raw-only.v1",
            "abi": dictionary.get("abi", ""), "validated_argument_bits": arguments,
            "source_plan_hash": dictionary["plan_hash"]}}
    if flags & 4:
        event["invocation_id"] = invocation
    if flags & 32:
        specs = dictionary.get("retention_key", [])
        if format_version == 2 and not specs:
            specs = [{"kind": "entry_return_address", "mask": (1 << 64) - 1}]
        if len(specs) != retention_part_count:
            raise ValueError("binary event retention dictionary mismatch")
        parts = [{**spec, "value": value} for spec, value in zip(specs, retention_values)]
        lane = "exact_promoted" if flags & 8 else "aggregate_first_sample"
        if retention_part_count == 1 and parts[0].get("kind") == "entry_return_address":
            event["retention_key"] = {"kind": "entry_return_address", "value": retention_entry_return,
                                      "hash": retention_hash, "parts": parts, "lane": lane}
        else:
            event["retention_key"] = {"kind": "composite", "hash": retention_hash,
                                      "entry_return_address": retention_entry_return,
                                      "parts": parts, "lane": lane}
    if flags & 64:
        exits = {int(row["hook_id"]): row for row in dictionary.get("exits", [])}
        if exit_hook_id not in exits:
            raise ValueError("binary event exit dictionary mismatch")
        exit_row = exits[exit_hook_id]
        event["normal_exit"] = {"exit_site_id": exit_row["exit_site_id"], "hook_id": exit_hook_id,
                                "contract": exit_row["contract"]}
    if legacy_size:
        event["legacy_snapshot"] = {"reader": dictionary.get("legacy_reader", ""),
            "offset": legacy_offset, "length": legacy_size, "read_failures": legacy_failures,
            "truncated": bool(flags & 16), "source_plan_hash": dictionary["plan_hash"]}
    return event


def unpack_records(payload, record_encoding="uc.record.v1", dictionaries=None):
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
        raw_metadata = payload[offset:offset + meta_size]
        event = (json.loads(raw_metadata) if record_encoding == "uc.record.v1"
                 else _binary_event(raw_metadata, dictionaries))
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

# A content-keyed cache lets analyzers, indexers and projections share one
# verified decompression/parse. The file is still read and hashed on every
# lookup: path/size/mtime alone cannot prove immutable evidence did not change.
_DECODE_CACHE: "OrderedDict[tuple, tuple]" = OrderedDict()
_DECODE_CACHE_MAX_BYTES = 256 * 1024 * 1024
_DECODE_CACHE_BYTES = 0
_DECODE_CACHE_LOCK = threading.Lock()


def event_dictionary_context(manifest: Path, records=None):
    """Read and validate one manifest once for a batch of chunk decodes.

    The digest remains part of every chunk cache key.  Callers may reuse this
    immutable context only for chunks in the manifest's own directory.
    """
    manifest = Path(manifest).resolve()
    manifest_bytes = manifest.read_bytes() if manifest.exists() else b""
    if records is None:
        records, errors = read_manifest(manifest) if manifest_bytes else ([], [])
        if errors:
            raise ValueError(f"event dictionary manifest invalid: {errors}")
    dictionaries = {}
    for record in records:
        if record.get("kind") != "event_dictionary" or record.get("schema") not in (
                "uc.EventDictionary.v2", "uc.EventDictionary.v3"):
            continue
        generation = int(record["generation"])
        for point in record.get("points", []):
            dictionaries[(generation, int(point["point_numeric_id"]))] = {
                **point, "plan_hash": record["plan_hash"]}
    return {"manifest": str(manifest), "manifest_digest": hashlib.sha256(manifest_bytes).digest(),
            "dictionaries": dictionaries}

def decode_chunk_file(path: Path, *, dictionary_context=None):
    """Verified decode of one sealed chunk file, memoized by file content."""
    global _DECODE_CACHE_BYTES
    path = Path(path).resolve()
    data = path.read_bytes()
    manifest = path.parent / "session.manifest"
    context = dictionary_context or event_dictionary_context(manifest)
    if Path(context["manifest"]) != manifest.resolve():
        raise ValueError("event dictionary context belongs to a different session")
    key = (str(path), hashlib.sha256(data).digest(), context["manifest_digest"])
    with _DECODE_CACHE_LOCK:
        cached = _DECODE_CACHE.get(key)
        if cached is not None:
            _DECODE_CACHE.move_to_end(key)
            return cached[0]
    result = decode_chunk(data, dictionaries=context["dictionaries"])
    weight = len(data) + result[0]["uncompressed_size"]
    with _DECODE_CACHE_LOCK:
        # Another decoder may have completed while this thread was outside the
        # lock.  Prefer its canonical cached object and do not double-account.
        cached = _DECODE_CACHE.get(key)
        if cached is not None:
            _DECODE_CACHE.move_to_end(key)
            return cached[0]
        # A changed sealed path must not retain an older decoded copy
        # indefinitely.  Cache mutation is serialized; decompression is not.
        for stale in [item for item in _DECODE_CACHE if item[0] == str(path) and item != key]:
            _, stale_weight = _DECODE_CACHE.pop(stale)
            _DECODE_CACHE_BYTES -= stale_weight
        if weight <= _DECODE_CACHE_MAX_BYTES:
            while _DECODE_CACHE and _DECODE_CACHE_BYTES + weight > _DECODE_CACHE_MAX_BYTES:
                _, (_, oldest_weight) = _DECODE_CACHE.popitem(last=False)
                _DECODE_CACHE_BYTES -= oldest_weight
            _DECODE_CACHE[key] = (result, weight)
            _DECODE_CACHE_BYTES += weight
    return result

def decode_chunk(data, *, max_uncompressed=256 * 1024 * 1024, dictionaries=None):
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
    if header["format_version"] != 1 or header["record_encoding"] not in ("uc.record.v1", "uc.record.v2"):
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
    events = list(unpack_records(payload, header["record_encoding"], dictionaries))
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

GENESIS_CHAIN = "0" * 64

def _chain_envelope(record: dict, prev_sha256: str):
    raw = canonical(record)
    return {"record": record, "sha256": hashlib.sha256(raw).hexdigest(), "prev_sha256": prev_sha256}

def append_manifest(path: Path, record: dict):
    """Validate the existing manifest and append one hash-chained envelope."""
    path = Path(path)
    chain_tail = GENESIS_CHAIN
    if path.exists():
        with path.open("rb") as stream:
            chain_seen = False
            for number, line in enumerate(stream, 1):
                if not line.endswith(b"\n"):
                    raise ValueError(f"manifest:{number}:uncommitted manifest tail")
                envelope = json.loads(line)
                digest = envelope["sha256"]
                if hashlib.sha256(canonical(envelope["record"])).hexdigest() != digest:
                    raise ValueError(f"manifest:{number}:manifest checksum")
                declared_prev = envelope.get("prev_sha256")
                if declared_prev is not None:
                    if declared_prev != chain_tail:
                        raise ValueError(f"manifest:{number}:manifest hash chain")
                    chain_seen = True
                elif chain_seen:
                    raise ValueError(f"manifest:{number}:manifest chain discontinued")
                chain_tail = digest
    envelope = _chain_envelope(record, chain_tail)
    with path.open("ab") as stream:
        stream.write(canonical(envelope) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return envelope["sha256"]

def read_manifest(path: Path):
    records, errors = [], []
    if not path.exists():
        return [], ["manifest_missing"]
    previous = GENESIS_CHAIN
    chain_seen = False
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            try:
                if not line.endswith(b"\n"):
                    raise ValueError("uncommitted manifest tail")
                envelope = json.loads(line)
                record = envelope["record"]
                if hashlib.sha256(canonical(record)).hexdigest() != envelope["sha256"]:
                    raise ValueError("manifest checksum")
                declared_prev = envelope.get("prev_sha256")
                if declared_prev is not None:
                    if declared_prev != previous:
                        raise ValueError("manifest hash chain")
                    chain_seen = True
                elif chain_seen:
                    raise ValueError("manifest chain discontinued")
                previous = envelope["sha256"]
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
    manifest_path = directory / "session.manifest"
    records, errors = read_manifest(manifest_path)
    dictionary_context = event_dictionary_context(manifest_path, records) if not errors else None
    declared = {record["file"]: record for record in records if record.get("kind") == "chunk"}
    sessions = [record["session_id"] for record in records if record.get("kind") == "session"]
    valid, seen = [], set()
    for path in sorted(directory.glob("chunk-*.ucb")):
        try:
            header, events = decode_chunk_file(path, dictionary_context=dictionary_context)
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
