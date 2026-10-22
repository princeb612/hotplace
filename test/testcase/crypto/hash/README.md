## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1106                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Hash, HMAC and transcript hash Testcases

## 1. What

This directory contains test sources for hash, hmac and transcript hash in hotplace. The category covers digest algorithms, keyed hashes, OTP-related RFC examples, and transcript-hash support.

## 2. How

### Procedure: generic digest wrapper

1. Select the digest algorithm and message/input bytes used by the case.
2. Invoke the OpenSSL digest wrapper and inspect the returned status and digest size.
3. The generic wrapper helper has a status-oriented path as well as a known-answer overload that accepts an expected digest. Do not describe every generic digest call as a known-answer test unless the expected bytes are supplied and compared.

### Procedure: run the RFC 4231 HMAC vectors

1. Iterate the fixed RFC 4231 table. Each row provides a key, message, and expected HMAC for SHA-224, SHA-256, SHA-384 and SHA-512.
2. Decode the key, message and four expected digests from hexadecimal strings into byte buffers.
3. Pass the same key/message pair to `test_hash_routine()` once for each digest algorithm.
4. Compare each calculated digest against that row's expected bytes. Verbose input dumps are diagnostic, not the oracle.

### Procedure: run HOTP (RFC 4226)

1. Open an `hmac_otp` context using the 20-byte ASCII key `12345678901234567890`, SHA-1 and a six-digit output.
2. Request codes for counters 0 through 9, appending each returned integer to an output vector, then close the context.
3. Compare both the output count and the complete ten-element integer array against the RFC's expected values.

### Procedure: run CMAC and TOTP vectors

- **CMAC (RFC 4493):** use each fixed AES key/message case, calculate the MAC, and compare the resulting tag bytes with the expected tag.
- **TOTP (RFC 6238):** supply the selected test key, timestamp/time-step and hash algorithm to the OTP calculation, then compare the generated code with the expected value for that case. Coverage is limited to the timestamps, widths and algorithms represented by the source.

### Procedure: transcript hash state equivalence

1. Build two transcript-hash input paths from the testcase's staged messages.
2. Update the transcript through the two paths and obtain their hash values at the designated intermediate state.
3. Assert that the hashes from the equivalent transcript states match.
4. Repeat through the builder-based transcript-hash path and compare its result with the reference path.
5. This is a consistency/equivalence check between paths; it is not a set of published fixed digest known-answer vectors.

2. The RFC-vector procedures are independent consumers even though they share one executable. Keep each vector's input layout and comparison contract distinct.

## 3. Evidence

### Source-level coverage

**1. RFC 4231 HMAC known-answer vectors**

~~~text
fixed key + message + four expected SHA-2 HMAC values
  -> decode key/message/expected values from hex
  -> test_hash_routine(SHA-224)
  -> compare calculated digest with expected bytes
  -> repeat for SHA-256 / SHA-384 / SHA-512
~~~

The supplied cases compare digest bytes. This does not mean every digest/provider combination is covered.

**2. RFC 4226 HOTP**

~~~text
key = "12345678901234567890"
  -> open HMAC-OTP (6 digits, SHA-1)
  -> get 10 codes for counters 0..9
  -> close context
  -> compare output count and entire uint32 array
     with the ten expected RFC values
~~~

This is an explicit whole-sequence comparison, stronger than checking only that each call returned.

**3. RFC 4493 CMAC**

~~~text
fixed AES key + each message vector
  -> open AES-CMAC context
  -> init / update / finalize
  -> close context
  -> assert result bytes == expected tag
~~~

**4. RFC 6238 TOTP**

~~~text
algorithm-specific test key + timestamp vectors
  -> calculate TOTP for selected SHA-1 / SHA-256 / SHA-512 cases
  -> compare produced code with expected vector values
~~~

The exercised timestamps, code widths and algorithms are bounded by the source table; this is not exhaustive time-boundary testing.

**5. Generic digest and transcript hash**

~~~text
generic digest:
  -> select digest / invoke wrapper
  -> status and feature checks
  -> known-answer evidence only where output bytes are compared

transcript hash:
  -> update transcript with staged input
  -> finalize/read hash
  -> compare only explicit digest/state assertions
~~~

Digest enumeration, successful initialization and logged intermediate bytes are not equivalent to a known-answer assertion. The generic HMAC API path should be assessed separately from RFC 4231 vectors.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation notes: `sdk/crypto/basic/digest/README.md`, `sdk/crypto/basic/mac/README.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 5. References

Source files in this directory:
- `test/testcase/crypto/hash/testcase_openssl_hash.cpp`
- `test/testcase/crypto/hash/testcase_rfc4226.cpp`
- `test/testcase/crypto/hash/testcase_rfc4231.cpp`
- `test/testcase/crypto/hash/testcase_rfc4493.cpp`
- `test/testcase/crypto/hash/testcase_rfc6238.cpp`
- `test/testcase/crypto/hash/testcase_transcript_hash.cpp`
