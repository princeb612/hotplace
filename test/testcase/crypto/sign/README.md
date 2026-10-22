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
# Digital signatures and MAC Testcases

## 1. What

This directory contains test sources for digital signatures and mac in hotplace. The category covers signature creation/verification, ECDSA, RSA signatures, HMAC, X.509 handling, ML-DSA, and SLH-DSA.

## 2. How

### Procedure: verify ECDSA supplied-signature vectors

1. Load a YAML row containing curve, digest, message, key components and expected `r`/`s` values.
2. Resolve the curve/digest hints, construct the EC key from the supplied components, and assemble the supplied signature in the source's `R || S` representation.
3. Pass that signature and message to the OpenSSL ECDSA verification path.
4. Where the builder is available, also ask the `crypto_sign` ECDSA builder to verify the same supplied signature.
5. Unsupported curve/digest cases are not positive verifications. This procedure validates a supplied signature; it does not necessarily compare generated signature bytes with the fixture.

### Procedure: ECDSA signature-size matrix

1. Iterate the selected EC key/curve and digest combinations in `testcase_ecdsa.cpp`.
2. Construct the signer and generate a signature for the fixed sample message.
3. Record the operation status and signature length reported by each case.
4. Treat this as an API/size exercise, not as a known-answer signature-byte test; unsupported combinations are reported separately.

### Procedure: DSA and RSA signature vectors

- **DSA:** load the YAML parameter/key and signature cases, construct or import the DSA key, verify the supplied signature, and exercise the source's generation/verification cases where those are present. Record the expected operation statuses for each fixture.
- **RSA CAVP:** the YAML consumer has separate RSA-key, PKCS#1 v1.5 and RSA-PSS cases. It loads the key/message/digest and padding parameters, performs signing or verification as specified by the row, and checks the operation result. Do not equate a successful verification of a supplied signature with equality of a newly generated signature to a fixed vector.

### Procedure: generated sign/verify matrix

1. Select the key identifier, signature algorithm and message defined by the test matrix.
2. Call the signing API. Some incompatible key/algorithm combinations intentionally expect signing to fail.
3. For successful signing paths, pass the produced signature to verification and check the expected result.
4. Where the source specifies a signature length, compare the produced length with that expected value.
5. Distinguish intentional negative cases from positive signature checks; a negative case passes only when the expected rejection is observed.

### Procedure: HMAC and JOSE HS256

1. Calculate a digest through the OpenSSL signing interface and compare it with the digest-wrapper result where the source includes that cross-check.
2. Exercise HMAC signing/verification with the supplied key and message.
3. Run the JOSE HS256 sign/verify path using the JWS context and inspect the operation statuses.
4. These API-level and cross-implementation checks are separate from fixed HMAC known-answer vectors in the hash testcase group.

### Procedure: certificate-based RSA sign/verify

1. Load the RSA private key and the public key from the certificate fixture.
2. Use the same sample message to sign with the private key and verify with the certificate's public key.
3. Exercise both PKCS#1 v1.5 and RSASSA-PSS paths, recording each result.
4. This testcase checks certificate/key loading and signature operations; it is not equivalent to a full certificate-chain or revocation validation test.

### Procedure: ML-DSA and SLH-DSA

1. Resolve each supported algorithm/key identifier in the active provider.
2. Sign the test message and record the returned status and signature length.
3. Verify the generated signature and record the verification status.
4. If the required OpenSSL/provider support is unavailable, the testcase reports unsupported; that is not a positive signature result.

## 3. Evidence

### Source-level coverage

**1. ECDSA supplied-signature vectors**

~~~text
YAML row: curve / digest / message / key coordinates / r / s
  -> resolve curve and digest hints
  -> build EC key from supplied components
  -> assemble signature = R || S
  -> openssl_sign.verify_ecdsa()
  -> record status
  -> crypto_sign_builder(ECDSA, digest).verify()
  -> record status if builder exists
~~~

This verifies acceptance of the supplied signature through two APIs. It does not generate a new signature and compare its bytes with the vector. Unsupported curve/digest paths are not positive verification.

**2. DSA and RSA signature vectors**

~~~text
YAML public key + message + supplied signature / algorithm parameters
  -> decode key and signature
  -> configure digest / RSA padding or DSA parameters
  -> verify supplied signature
  -> assert returned result/status
~~~

Only rows actually consumed by the source count. Verification of a supplied signature is distinct from testing signature generation.

**3. Generated sign/verify matrix**

~~~text
key fixture + message + signature category + digest + expected outcome
  -> crypto_sign_builder
  -> sign()
  -> if expected positive: check success
     if expected negative: assert sign failure
  -> verify generated signature
  -> check expected verification outcome
  -> for selected EC cases, compare signature length
~~~

The matrix includes expected failures, including selected curve/digest pairings. Negative expectations are intentional cases, not ordinary failures; the harness expt category should remain distinct from pass.

**4. HMAC and JOSE HS256**

~~~text
message -> openssl_hash SHA-256 -> compare with EVP_Digest result
key + message -> HMAC operation -> check operation status
key + message -> sign_hmac() -> verify_hmac() -> check statuses
key + message -> JOSE HS256 sign() -> verify() -> check statuses
~~~

The first path cross-checks two SHA-256 implementations. The shown HMAC calculation path records operation status but does not compare HMAC bytes with a fixed expected MAC. Sign/verify paths check API outcomes, not a known-answer signature string.

**5. ML-DSA / SLH-DSA / X.509**

~~~text
algorithm/provider available?
  -> run signature or certificate operation
  -> check explicit status/result for that case
  -> unavailable / unsupported remains distinct from successful verification
~~~

These are separate contracts from ECDSA/DSA/RSA supplied-signature vectors. Do not count certificate parsing or algorithm enumeration as signature-vector verification.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation notes: `sdk/crypto/basic/sign/README.md`, `sdk/crypto/basic/mac/README.md`
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 5. References

Source files in this directory:
- `test/testcase/crypto/sign/testcase_crypto_sign.cpp`
- `test/testcase/crypto/sign/testcase_ecdsa.cpp`
- `test/testcase/crypto/sign/testcase_hmac.cpp`
- `test/testcase/crypto/sign/testcase_mldsa.cpp`
- `test/testcase/crypto/sign/testcase_rsassa.cpp`
- `test/testcase/crypto/sign/testcase_slhdsa.cpp`
- `test/testcase/crypto/sign/testcase_x509.cpp`
- `test/testcase/crypto/sign/testvector_dsa.cpp`
- `test/testcase/crypto/sign/testvector_ecdsa.cpp`
- `test/testcase/crypto/sign/testvector_rsassa.cpp`
