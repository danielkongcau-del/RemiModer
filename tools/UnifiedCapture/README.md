# UnifiedCapture

UnifiedCapture is a configurable local evidence recorder for Windows x64 processes. It is designed around immutable capture generations, bounded callback work, explicit hook ownership, independent loss accounting, and sealed local evidence chunks.

## Components

- `native/` implements the C++20 recorder and owned-fixture executables.
- `uc/` implements schemas, validation, storage verification, indexing, projections, and mechanical callsite analysis.
- `capturectl.py` provides the local control interface.
- `d0ctl.py` and `entryctl.py` provide resumable single-entry and multi-entry orchestration.
- `d0_analyze.py` and `entry_analyze.py` validate sealed sessions without promoting stronger claims than the evidence supports.
- `tests/` contains generic unit and native-fixture tests.

## Dependencies and build output

`bootstrap.py` downloads fixed public dependencies and verifies their digests. Downloaded dependencies, binaries, plans, target bindings, baselines, and test output are deliberately ignored.

The library is an observation component, not an injector. Target loading is outside this repository. Mutation hooks, protection changes, and target-specific evidence are outside the public scope.

## Evidence boundaries

Raw ABI evidence and semantic interpretation are distinct. A decoded callsite is not automatically a semantic caller identity. A type identity is not execution evidence. File integrity is not semantic completeness. Unobserved events remain unknown unless the exact observation point had complete, lossless coverage for the stated window.
