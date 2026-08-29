# UnifiedCapture

This repository contains a generic, local-first runtime evidence recorder for Windows x64 processes.

The public tree intentionally excludes target binaries, extracted assets, runtime captures, decoded metadata, target-specific plans, addresses, hashes, names, and research conclusions. Those materials remain local and are blocked by repository ignore rules.

## Repository layout

- `tools/UnifiedCapture/native/` — C++20 in-process recorder, hook lifecycle, bounded reads, loss accounting, and evidence storage.
- `tools/UnifiedCapture/uc/` — Python plan validation, immutable storage verification, indexing, and analysis helpers.
- `tools/UnifiedCapture/tests/` — generic unit and owned-fixture integration tests.
- `tools/UnifiedCapture/schemas/` — versioned public schemas.
- `docs/` — generic architecture and local-data policy.

Target software is started and controlled by its owner. The recorder does not include an injector, does not disable protection software, and does not alter target arguments or return values.

## Local-only boundary

Do not force-add ignored files. In particular, never commit anything under `extracted/`, `local-only/`, target installation directories, source-asset directories, downloaded tool directories, or UnifiedCapture's local plans and output folders.

No license is granted for third-party or target-derived material.
