# UnifiedCapture

UnifiedCapture is a configurable local evidence recorder for Windows x64 processes. It is designed around immutable capture generations, bounded callback work, explicit hook ownership, independent loss accounting, and sealed local evidence chunks.

## Components

- `native/` implements the C++20 recorder and owned-fixture executables.
- `uc/` implements schemas, validation, storage verification, indexing, projections, and mechanical callsite analysis.
- `capturectl.py` provides the local control interface.
- `d0ctl.py` and `entryctl.py` provide resumable single-entry and multi-entry orchestration.
- `campaignctl.py` qualifies the union of several entry plans once, then switches their immutable generations in one target process with explicit armed/complete marks.
- `p1_bind_campaign_callsites.py` binds that campaign to mechanically decoded static callsites while preserving unresolved indirect callers for runtime resolution.
- `p1_merge_entry_plans.py` and `p1_reframe_campaign.py` change activation-unit granularity without repeating an already exact physical-site qualification.
- `d0_analyze.py` and `entry_analyze.py` validate sealed sessions without promoting stronger claims than the evidence supports.
- `tests/` contains generic unit and native-fixture tests.

## Dependencies and build output

`bootstrap.py` downloads fixed public dependencies and verifies their digests. Downloaded dependencies, binaries, plans, target bindings, baselines, and test output are deliberately ignored.

The library is an observation component, not an injector. Target loading is outside this repository. Mutation hooks, protection changes, and target-specific evidence are outside the public scope.

## Evidence boundaries

Raw ABI evidence and semantic interpretation are distinct. A decoded callsite is not automatically a semantic caller identity. A type identity is not execution evidence. File integrity is not semantic completeness. Unobserved events remain unknown unless the exact observation point had complete, lossless coverage for the stated window.

## Safety gates and attribution

- Code observation supports instruction probes and evidence-qualified entry/exit probe pairs. Function call listeners are not accepted by either plan schema or the runtime.
- Slot replacement refuses activation under CFG unless the plan explicitly owns the indirect-dispatch risk (`accept_cfg_indirect_dispatch_risk`).
- Read programs support `scalar`/`relative`/`block`/`array`/`string` operations at explicit `enter` or `leave` phases. Leave reads may use saved entry registers through `entry:<register>`; dependencies must remain within one phase. `when` predicates remain entry-only, and filtered events are counted (`filtered_by_plan`), never silently dropped.
- Callbacks observed while admission is closed are counted in a durable `admission_window` note.
- Storage failures persist a `storage_error` manifest note including events lost to the failing seal.
- A detected persistence failure closes capture admission and reports `STORAGE_FAILED`; explicit stop still performs independent ownership-aware hook cleanup.
- Manifest lines are hash-chained (`prev_sha256`); deletion or reordering of sealed history is detectable offline.
- `stop --force` performs a terminal unclean seal for wedged frames. Late callbacks keep shared ownership, and hooks/resources that cannot be proved safe to detach remain resident until process exit; the observer refuses reactivation in that process.
- CLI tools share exit-code discipline: 0 ok, 1 observer rejection, 2 internal error.
