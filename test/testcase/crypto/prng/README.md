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
# Randomness, nonces and tokens Testcases

## 1. What

This directory contains test sources for randomness, nonces and tokens in hotplace. The category covers random bytes, nonce generation, and token generation.

## 2. How

### Procedure: exercise the random-number API

1. Construct an `openssl_prng` instance.
2. Call `rand32()` 30 times. The test retains or prints values for observation; verbose mode controls diagnostic output.
3. Generate 16-byte nonces using Base16 encoding for 30 iterations, then call the related `rand(16, Base16, true)` path for another 30 iterations.
4. Generate Base64URL tokens of length 16 for 30 iterations, then call `rand(16, Base64URL, true)` for another 30 iterations.
5. Observe the return/report path separately from printed values. The test does not compare against deterministic expected random values, retain and check every output's length/alphabet, assert uniqueness, or run statistical tests.

2. These are API exercise loops, not a randomness-quality test. Repeating the call a fixed number of times does not establish entropy, distribution, collision resistance or cryptographic suitability.

## 3. Evidence

### Source-level coverage

**1. Random 32-bit values**

~~~text
construct openssl_prng
  -> call rand32() 30 times
  -> retain latest value / optional verbose log
  -> report ret initialized to success
~~~

There is no expected-value comparison or statistical assertion.

**2. Nonce generation**

~~~text
nonce(16, Base16) x 30
  -> optional log of latest nonce
rand(16, Base16, true) x 30
  -> optional log of latest value
  -> report ret initialized to success
~~~

The source does not assert every output's length/alphabet, uniqueness, or collision rate.

**3. Token generation**

~~~text
token(16, Base64URL) x 30
  -> optional log of latest token
rand(16, Base64URL, true) x 30
  -> optional log of latest value
  -> report ret initialized to success
~~~

The token is not decoded and checked against a format oracle. These loops show API invocation only; they do not demonstrate entropy quality, distribution, collision resistance, or cryptographic suitability.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation notes: `sdk/crypto/basic/backend.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 5. References

Source files in this directory:
- `test/testcase/crypto/prng/testcase_random.cpp`
