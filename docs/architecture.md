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
- A clean file checksum proves file integrity, not semantic correctness.
- Zero events can only establish absence inside a covered, lossless window; it cannot prove that a behavior never occurred.
- Hook removal is ownership-aware and must not overwrite a third party's later modification.
- Explicit stop drains accepted calls before resources are released.

The public source provides generic mechanisms only. Target bindings, evidence manifests, addresses, identifiers, and conclusions are intentionally local.
