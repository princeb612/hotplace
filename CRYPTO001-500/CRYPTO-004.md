# CRYPTO-004 — Authenticode CRL source-comment mismatch

- **Area:** `sdk/crypto/authenticode`
- **Status:** Recheck
- **Kind:** Source-maintenance follow-up
- **Source basis:** `authenticode_verifier.hpp` comment and the behavior described by the Revision 1107 source-tree docs.

## Background

The source-tree documentation recorded that `authenticode_verifier.hpp` retains a comment describing CRL revocation verification as temporarily disabled / file-download-related, while the current implementation contains CRL configuration and download/cache paths. The mismatch can mislead a future reader about whether CRL checking is actually present.

The implementation of CRL retrieval and the completeness of a production revocation policy are separate questions. This record concerns comment accuracy, not a claim that the existing revocation flow is complete.

## Next check

1. Re-open the exact header comment and current CRL setup/retrieval path.
2. Update the comment to describe current code, or retain historical context explicitly as history.
3. Keep claims about full revocation policy separate from the presence of CRL retrieval, store flags, and decoded CRL objects.

## History

- 2026-10-23: Migrated the explicit “keep source comments and runtime behavior aligned” note from `authenticode_verifier.md`. No code or tests changed.
