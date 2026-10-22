# CRYPTO-001 — JOSE decryption result contract and multi-recipient behavior

- **Area:** `sdk/crypto/jose`
- **Status:** Open
- **Kind:** Source-review finding; regression-test candidate
- **Source basis:** JOSE README review on `docs/sdk-source-tree-review-1107`; findings were read from source/documentation but not runtime-reproduced in this session.

## Background

The JOSE README's source-review section identified three related questions in the multi-recipient JWE decryption path:

1. `decrypt()` initializes its `bool& result` output to `false` but apparently does not set it to `true` when the return status indicates success. Existing RFC 7516 tests generally assert the return code rather than this output parameter.
2. Recipient attempts contribute boolean results, and the implementation appears to accept only when a deduplicated result list contains a single `true`. A mix of failed and successful attempts may therefore return `cipher_failure` rather than accept a usable successful recipient.
3. The output buffer is reused across attempts, so a later failed attempt may affect the plaintext left in the output after an earlier success.

These observations are not claims that runtime behavior was reproduced. Recheck the exact current source and contract before changing code.

## Next check

1. Inspect the public `decrypt()` overloads and the concrete JWE recipient loop.
2. Define the `bool& result` contract alongside the return status: whether it mirrors success, recipient acceptance, or another condition.
3. Test single-recipient success/failure and mixed-recipient cases (first fails/second succeeds and vice versa).
4. Verify that plaintext output is deterministic on success and well-defined/cleared on total failure.
5. Keep source fixes and focused regression tests separate from this documentation finding.

## History

- 2026-10-23: Migrated from a source-tree README subsection. No code change or runtime reproduction was performed.
