# CRYPTO-001 — JOSE decryption result contract and multi-recipient behavior

- **Area:** `sdk/crypto/jose`
- **Status:** Open
- **Kind:** Source-review finding; focused regression-test candidate
- **Current source basis:** `master` at [`4ff020d8f4db6be2639f8dd11ad39c4faa0904d8`](https://github.com/princeb612/hotplace/commit/4ff020d8f4db6be2639f8dd11ad39c4faa0904d8) (`hotplace rev.1108`).
- **Original source basis:** JOSE README review on `docs/sdk-source-tree-review-1107`; the original notes were not runtime-reproduced.

## Background

The original review grouped three questions about `json_object_encryption::decrypt()`. Rechecking current `master` separates one point that is already handled in source from two remaining questions.

## Current findings

### 1. `bool& result` and return status — source-level behavior is present

In current `sdk/crypto/jose/json_object_encryption.cpp`, `decrypt()` sets `result = false` at entry, then in `__finally2` sets it to `true` exactly when the final `ret` equals `errorcode_t::success`.

```cpp
__finally2 {
    json_object_signing_encryption::clear_context(handle);
    if (errorcode_t::success == ret) {
        result = true;
    }
}
```

So the original claim that the function never sets the output to true is stale against Revision 1108. At source level, `result` mirrors the final return status. This does **not** establish that tests have asserted the output parameter: the RFC 7516 helper passes `result` to `decrypt()`, but the shown test assertion checks `ret`; the RFC 7520 JWE helper likewise asserts `ret`.

Disposition for this sub-question: **source behavior confirmed; test assertion coverage not confirmed**. Do not keep this as an unimplemented source defect.

### 2. Mixed recipient outcomes — still needs contract confirmation

The recipient loop calls `dodecrypt()` for each recipient and appends whether each attempt returned success to `results`. Afterwards it calls `results.unique()` and accepts only if the resulting list contains exactly one `true`; otherwise it returns `errorcode_t::cipher_failure` (or `not_supported` when there were no attempts).

`std::list<bool>::unique()` removes only adjacent duplicate values. Therefore a sequence containing both `true` and `false` remains mixed and is rejected, regardless of order. This is confirmed by source inspection; whether this is a defect depends on the intended contract for this API when a JWE has multiple recipients. The RFC 7520 testcase includes a multi-recipient example, but its helper asserts the return code and does not explicitly isolate mixed success/failure recipient attempts.

### 3. Output buffer across recipient attempts — behavior remains unverified

The same `output` buffer is passed to successive `dodecrypt()` calls. The outer loop does not explicitly clear or stage plaintext between recipient attempts. Whether a failed later attempt can change or leave ambiguous the plaintext produced by an earlier successful attempt depends on the lower-level decrypt path and should not be described as a reproduced failure.

## Useful flow

```text
decrypt()
  |
  +-- output.clear(); result = false
  |
  +-- parse JWE and try each recipient
  |     |
  |     +-- dodecrypt(..., output)
  |     +-- append (attempt status == success) to results
  |
  +-- no attempts -> not_supported
  |
  +-- results.unique()
  |     |
  |     +-- exactly [true] -> keep ret == success
  |     +-- otherwise       -> cipher_failure
  |
  +-- finally: clear context
  |     +-- if ret == success -> result = true
  |
  +-- return ret
```

## Next check

1. Decide/document the intended multi-recipient contract: does one valid recipient suffice, or must all attempted recipients have the same outcome?
2. Use a focused fixture where recipient attempts produce mixed outcomes in both orders; assert both `ret` and `result`.
3. Inspect the lower-level `dodecrypt()` and cryptographic decrypt failure paths to determine whether a failed attempt can modify `output`. If needed, test that successful plaintext is stable and total-failure output is well-defined.
4. Keep any source fix and focused testcase change as separate decisions. This workspace records findings only; do not edit product source or tests here.

## History

- 2026-10-23: Migrated from the source-tree review. Original observations were not runtime-reproduced.
- 2026-10-23: Rechecked current `master` Revision 1108 (`4ff020d8f4db6be2639f8dd11ad39c4faa0904d8`). Confirmed that `result` is set true when final `ret` is success; retained the multi-recipient acceptance and output-buffer questions as open. No build or test was run in this follow-up session.
