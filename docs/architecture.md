# Architecture

UnifiedCapture separates generic instrumentation from target-specific evidence.

```text
validated capture plan
        |
immutable compiled generation
        |
read-only observation backend
        |
bounded event channel + independent loss counters
        |
sealed local chunks
        +-- rebuildable query index
        +-- optional timeline projection
        +-- source-bound local analysis
```

## Design constraints

- The loader and the instrumentation backend are separate concerns.
- Capture plans are validated and compiled before callbacks run.
- Plan revision and activation generation are distinct identities.
- Entry callbacks preserve raw ABI evidence; semantic interpretation is a separate layer.
- Object addresses, object candidates, instances, and entity identities are not interchangeable.
- Coverage and loss are recorded independently from ordinary event delivery.
- Deliberate plan-side filtering (entry predicates) is accounted separately from loss.
- Callbacks observed while admission is closed are counted, not discarded.
- A clean file checksum proves file integrity, not semantic correctness.
- Zero events can only establish absence inside a covered, lossless window; it cannot prove that a behavior never occurred.
- Hook removal is ownership-aware and must not overwrite a third party's later modification.
- Explicit stop drains accepted calls before resources are released; a forced stop records what it reclaimed, seals with `STOPPED_FORCED`, and never claims clean cleanup.
- Backends with known failure modes activate only under explicit plan-level risk acceptance.
- Sealing and manifest durability run off the callback path; the capture-time seal backlog is bounded and applies nonblocking, loss-accounted backpressure.
- Control acknowledgements for plan/mark/stop intent wait for durable metadata; final session sealing proceeds asynchronously and remains queryable as `DRAIN_PENDING`.
- Evidence manifests are hash-chained so silent truncation or reordering is detectable.
- Storage failures are persisted with the events they dropped, so disk failure and crash remain distinguishable offline.
- A persistence failure closes admission immediately and reports `STORAGE_FAILED`; hooks remain owned until an explicit stop can clean them without falsely claiming a sealed session.

The public source provides generic mechanisms only. Target bindings, evidence manifests, addresses, identifiers, and conclusions are intentionally local.
