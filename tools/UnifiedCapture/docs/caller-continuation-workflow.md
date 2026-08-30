# Exact caller-continuation workflow

This workflow closes a bounded normal-return relationship without claiming a
complete callee exit set. XXMI loads `UnifiedCapture.dll`; all later operations
use the local control pipe and immutable local evidence files.

## Evidence meaning

At a qualified callee entry, `[RSP]` supplies the architectural return address.
Only callers already present in a clean retained session may be exact-promoted.
For a paired observation, the runtime opens a frame only for an exact caller and
binds that frame only to the matching return address. A probe at that address
therefore records:

`normal_return_to_observed_callsite_continuation`

It does not prove that every callee exit was enumerated. Exceptions, nonlocal
unwinds and calls that never return do not manufacture a leave event.

## One-process sequence

1. Run the retained discovery plan and stop it cleanly.
2. Finalize the retained session and exact-promote only caller rows already in
   that evidence. To take every mechanically eligible row without a manual
   semantic selection step:

   ```powershell
   python retained_exact_selection.py --inventory <retained-caller-inventory.json> --out <selection-directory>
   ```

   The resulting selection is scope-only and is not treated as game evidence.
3. Prepare continuation candidates and a qualification request:

   ```powershell
   python caller_continuation_prepare.py --plan <exact-v2-plan.json> --out <prepared-directory>
   ```

4. Without closing the game process, qualify the prepared sites. A clean stop
   causes the observer to open a new evidence session; no generation is
   published during qualification:

   ```powershell
   python capturectl.py qualify-sites --pid <pid> <prepared-directory>\qualification-request.json `
     --out <qualification-evidence.json>
   ```

5. Compile the process-bound paired plan:

   ```powershell
   python caller_continuation_apply.py --plan <exact-v2-plan.json> `
     --candidates <prepared-directory>\caller-continuation-candidates.json `
     --qualification-evidence <qualification-evidence.json> --out <activated-directory>
   ```

6. Apply `capture-plan.caller-continuations.json`, repeat the broad action
   sequence once, then stop and analyze normally.

The prepare report lists unsafe or overlapping observations and leaves them
entry-only. It never silently narrows an observation's exact caller set. A
forced/uncertain stop cannot use the same-process continuation path.
