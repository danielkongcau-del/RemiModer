# Controller exact-closure performance incident (2026-08-31)

## Outcome

The process-bound revision-1 run is rejected as a complete evidence session. Entering the trial froze the game and the process was exited, so the archived store correctly reports `session_tail_unknown` and has no clean `session_end`.

Archived local original:

`E:\ZZZ\extracted\analysis\controller-exact-closure-runtime-20260831-p32900-v1\aborted-session-97ede9b93e0ff868c22b7a90309c293b`

The 127 sealed chunks remain independently verifiable and contain 332,651 events (251,165,188 raw bytes; 25,538,724 stored bytes). They may be used as incomplete diagnostic evidence, but not as a clean coverage window.

## Root cause

Revision 1 reintroduced `SelectedEncryptedApiTarget@0xacdfe0` as a full-retention observation with XMM capture. A live status snapshot before the trial already showed about 2,852 callbacks per second, 56,033 captured parent records in roughly 20 seconds, and about 43 MB of encoded data. Its read program also performed guarded memory reads on every callback. The exact child invoker was only about 38 callbacks per second.

This contradicted the existing local warning in `docs/controller-next-runtime-closure-run-20260830-v1.md`, which had already classified `0xacdfe0` as a shared high-frequency target unsuitable for full recording.

Frida's official performance guidance likewise says callback choice materially affects overhead, warns against intercepting extremely hot functions, recommends native callbacks for hot paths, and recommends batching output. Gum also distinguishes an instruction probe from a call listener with an empty leave callback; the former avoids return trapping. Sources:

- https://frida.re/docs/javascript-api/#performance-considerations
- https://frida.re/docs/gum/class.Interceptor.html

## Corrective changes

1. Revision 2 removes the shared `0xacdfe0` parent observation. The required dispatch relation is preserved by source-verified instructions at `0xACDFF7..0xACE052`, the exact child invoker at `0x4E30`, and the qualified normal-return continuation at `0xACE055`.
2. The source plan sets `capture_xmm=false`; none of its current interpretations consumes vector state.
3. Raw-register entry predicates now have a native early-filter path before pool allocation, XMM copying, stack-return reads, pairing, and persistence. Filtered counts remain explicit. Mutable-memory predicates are not duplicated by this optimization.
4. Full-retention entry-only probes no longer perform an unconditional `[RSP]` safe read or initialize pairing bookkeeping.
5. No automatic duration, event-count cutoff, rate cutoff, sampling, or hidden safety lock was added.

## Verification

- Python suite: 125 passed.
- Native predicate hot-path fixture: 20,000 target calls with three logical predicate subscriptions, 60,005 accounted filters, four retained events, 0.0132 seconds (about 1.52 million target calls/second) in the owned fixture run.
- Probe-pair/SEH matrix: passed.
- Retention concurrency: 80,000 callbacks, one key, zero `retention_key_busy`.
- Async store and 20-case robustness matrix: passed.

The fixture rate is a regression signal, not a promise of game performance. The next game run must first perform an idle/menu compatibility check and inspect per-point rates before entering the trial.
