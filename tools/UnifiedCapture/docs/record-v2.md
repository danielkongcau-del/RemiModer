# `uc.record.v2` compact event metadata

The `.ucb` framing, chunk hash, CRC32C, compression, immutable sealing, and
manifest chain are unchanged. A v2 chunk replaces each record's repeated JSON
metadata with little-endian binary metadata; the raw read blob remains the
second framed payload. `event_dictionary` records in the hash-chained manifest
bind `(generation, point_numeric_id)` to point/read/exit names and the source
plan hash. JSON is an offline projection, not the evidence original.

Fixed prefix (`<8sIIII8Q9I`, 124 bytes):

1. magic `UCEVT002`;
2. version, kind code, point numeric id, thread id;
3. event id, generation, QPC, read-end QPC, invocation id, observed parent,
   retention key, raw stack marker;
4. flags, GPR mask, XMM mask, validated-argument mask, exit hook id, legacy
   offset, legacy length, legacy read failures, read-result count.

Variable fields follow in mask-bit order: selected 64-bit GPRs, selected 64-bit
validated arguments, selected raw 16-byte XMM registers, then one
`<QQQIII>` read result per dictionary read id. Unknown tails, missing
dictionaries, mismatched read counts, and unknown kind/exit ids are rejected.

Kind codes are `1=probe`, `2=enter`, `3=leave`,
`4=frame_absent_after_observed_point`, and `5=aggregate_entry_sample`.
Flags are `parent_known=1`, `exceptional=2`, `has_invocation=4`,
`retention_exact=8`, `legacy_truncated=16`, `has_retention=32`, and
`has_normal_exit=64`.
