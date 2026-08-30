# `uc.record.v3` compact event metadata

The `.ucb` framing and `record_encoding=uc.record.v2` container remain
unchanged. Version 3 changes only the binary metadata carried by each record so
that a retained event can preserve a collision-checked raw composite key.
`uc.EventDictionary.v3` binds the ordered key-part definitions to each point.

Fixed prefix (`<8sIIII9Q10I`, 136 bytes):

1. magic `UCEVT003`;
2. version, kind code, point numeric id, thread id;
3. event id, generation, QPC, read-end QPC, invocation id, observed parent,
   retention-key fingerprint, raw stack marker, architectural entry return
   address;
4. flags, GPR mask, XMM mask, validated-argument mask, exit hook id, legacy
   offset, legacy length, legacy read failures, read-result count, retention
   key-part count.

The fixed prefix is followed by the raw 64-bit retention key parts in
dictionary order, then selected GPRs, validated arguments, XMM registers, and
read results as in v2. The fingerprint is an in-process table locator only;
key equality is established by the complete ordered raw parts. Hash equality
alone never establishes object or entity identity.

The first key part is always the architectural entry return address. Optional
parts are masked raw register bits. They are evidence values, not inferred
types. A callback that encounters an unfinished concurrent key publication is
reported as `retention_key_busy`; it is not blocked or silently inserted as a
duplicate key.

The Python decoder remains backward-compatible with `UCEVT002` and projects
both versions to `uc.event.v1` JSON. For composite keys the projection includes
`kind=composite`, the fingerprint, entry return address, all raw parts, and the
retention lane.

For an exact-promoted probe pair, the leave record inherits the entry's full
retention identity and slot index. Runtime summaries distinguish
`exact_entries_persisted`, `exact_normal_exits_persisted`, and
`exact_pairs_persisted`; pair-stream completeness is based on persisted pairs,
not on the entry count alone. A persistence failure on either half breaks the
exact stream at the first known failure QPC.
