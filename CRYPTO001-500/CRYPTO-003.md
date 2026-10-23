# CRYPTO-003 — Authenticode digest error propagation

- **Area:** `sdk/crypto/authenticode`
- **Status:** Open
- **Kind:** Source behavior / error-contract follow-up
- **Source basis:** `sdk/crypto/authenticode/README.md` and `authenticode_verifier.md` on `docs/sdk-source-tree-review-1107`.

## Background

Both Authenticode documents note that `authenticode_verifier::verify()` calls the selected engine's `digest()` method without checking its returned `return_t`. Consequently, a digest-calculation error may not be propagated as its original error code; the later digest comparison can determine the visible failure.

This is a source-level observation. The exact downstream behavior and all digest-engine implementations have not been exhaustively verified here.

## Next check

1. Inspect `verify()` and all registered engine `digest()` implementations.
2. Decide whether the verifier should propagate a digest error directly or intentionally collapse it into a verification failure.
3. If the contract changes, add a focused failure-path testcase that distinguishes digest failure from digest mismatch.
4. Keep the distinction between the returned `return_t` and the coarse `verify_ok` / `verify_fail` output explicit.

## History

- 2026-10-23: Migrated the “behavior to revisit” note out of the Authenticode source-tree docs. No code or tests changed.
