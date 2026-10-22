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
# Key derivation functions Testcases

## 1. What

This directory contains test sources for key derivation functions in hotplace. The category covers HKDF and RFC-based KDF vectors including PBKDF2, scrypt, Argon2, and CMAC-based derivation cases.

## 2. How

### Procedure: inline HKDF known-answer case

1. Begin the `hkdf` testcase and create an `openssl_kdf` wrapper.
2. Configure SHA-256, output length 10, password/IKM `secret`, salt `salt` and info `label`.
3. Call `hmac_kdf()` to derive the output into a byte vector.
4. Decode the expected hexadecimal string `2ac4369f525996f8de13` and assert exact byte equality with the derived output.
5. Verbose mode can print the derived bytes, but the equality assertion is the decisive check. This inline example covers one parameter set.

### Procedure: RFC 5869 HKDF and RFC 4615 CMAC-KDF vectors

1. The corresponding YAML consumer loads each vector row from its fixture and reads the row's algorithm, input keying material/key, salt, info/message, requested length and expected result fields.
2. Decode encoded binary fields and configure the digest or PRF and output length for that vector.
3. Execute the selected derivation/MAC operation.
4. Compare the result bytes with the expected output wherever the consumer asserts them; inspect the individual source for its exact field mapping and comparison.
5. Do not treat fixture row count as proof that every row was reached or passed. The actual consumer invocation and report are needed for runtime coverage claims.

### Procedure: optional PBKDF2 and scrypt cases

1. Run the crypto executable with `-s`; without this option, `sample.cpp` does not call `testcase_rfc6070()` or `testcase_rfc7914()`.
2. The RFC 6070 case supplies password, salt and iteration/output parameters to PBKDF2 and compares the derived key against its expected vector.
3. The RFC 7914 case supplies the scrypt password, salt and work-factor parameters, derives the key, and checks the vector-defined result.
4. Because these are slower paths, distinguish a default-run report from one generated with `-s`.

### Procedure: optional Argon2

1. Run with `-argon2` to dispatch `testcase_rfc9106()`.
2. The test applies the selected RFC 9106 parameter sets to Argon2 and checks the result fields asserted by that source.
3. Without the flag, those calls are skipped; a default report cannot be cited as evidence that the Argon2 vectors executed.

2. A status check and exact derived-key equality are not interchangeable. The source-level coverage section below records which oracle each path uses.

## 3. Evidence

### Source-level coverage

**1. Inline HKDF known answer**

~~~text
password = "secret"
salt = "salt"
info = "label"
digest = SHA-256, output length = 10
  -> openssl_kdf.hmac_kdf()
  -> assert decoded expected bytes
     2ac4369f525996f8de13 == derived output
~~~

This is a direct byte-for-byte assertion for one parameter set.

**2. YAML-driven RFC 5869 / RFC 4615**

~~~text
YAML vector row
  -> read algorithm, IKM/key, salt, info/message, expected output
  -> decode binary fields
  -> configure digest / PRF and requested output length
  -> derive key or MAC
  -> compare computed bytes with expected bytes
~~~

Each consumer has its own field mapping and assertion. YAML schema and row count alone do not prove all vectors were executed.

**3. PBKDF2 and scrypt — optional**

~~~text
-s supplied?
  yes -> testcase_rfc6070() / testcase_rfc7914()
          -> use supplied password, salt, iteration/work factor
          -> derive key -> compare with expected vector
  no  -> these functions are not called by sample.cpp
~~~

**4. Argon2 — optional**

~~~text
-argon2 supplied?
  yes -> testcase_rfc9106() -> run selected RFC 9106 parameters
          -> compare derived output where asserted
  no  -> no Argon2 path from the main dispatcher
~~~

A successful return status and exact derived-key equality are different assertion strengths. Do not claim optional KDF vectors ran without invocation evidence.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation notes: `sdk/crypto/basic/kdf/README.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 5. References

Source files in this directory:
- `test/testcase/crypto/kdf/testcase_hkdf.cpp`
- `test/testcase/crypto/kdf/testcase_rfc6070.cpp`
- `test/testcase/crypto/kdf/testcase_rfc7914.cpp`
- `test/testcase/crypto/kdf/testcase_rfc9106.cpp`
- `test/testcase/crypto/kdf/testvector_rfc4615.cpp`
- `test/testcase/crypto/kdf/testvector_rfc5869.cpp`
