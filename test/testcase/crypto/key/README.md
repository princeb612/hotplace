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
# Keys and key exchange Testcases

## 1. What

This directory contains test sources for keys and key exchange in hotplace. The category covers key import/export, key generation, DER/JWK/CWK representations, curves, DH/EC, HPKE, and key-share/vector paths.

## 2. How

### Procedure: generate and identify keys

1. The key-generation test requests named key families through the key-generation interface.
2. Enumerate the returned key objects and inspect their selected key identifiers and OpenSSL key-type NIDs.
3. Compare the identifiers/NIDs for which the source has explicit expected values. Key dumps are diagnostic, not parameter-by-parameter validation.
4. The YAML key-generation consumer is a separate path: it reads the vector's key type and material/metadata and checks the generated or reconstructed key against the fixture's explicit checks.

### Procedure: encode and decode key representations

1. Select the representation used by the test, such as DER or raw public/private key material, or JWK/CWK.
2. For JWK/CWK, parse the encoded fields and check the selected key material; the source includes an explicit check that a leading zero in an EC coordinate is preserved.
3. For the DER testcase, parse the RFC 8448 server-certificate sample, obtain the certificate/key representation, serialize it to DER and compare the encoded bytes with the expected DER sample.
4. For EC compressed/uncompressed points, decode the supplied coordinate/point forms and compare X, Y, private scalar and encoded point bytes where asserted. Unsupported/unavailable point lookups are distinct from equality passes.
5. Successful import/export alone does not prove canonical encoding or complete parameter preservation.

### Procedure: DH and EC agreement

1. Construct the RFC 7748 Curve25519/X25519 and Curve448/X448 inputs from the fixed test values.
2. Derive the shared secret through the two corresponding sides.
3. Compare both derived secrets with each other and with the RFC expected shared-secret bytes.
4. The EC point tests are a different contract: they check coordinate extraction and compressed/uncompressed point encodings rather than shared-secret agreement.

### Procedure: HPKE

1. Follow the RFC 9180 test's receiver key-pair setup and sender/receiver roles.
2. The sender uses the selected KEM/KDF/AEAD suite to encapsulate and encrypt the sample plaintext with the configured context/AAD.
3. The receiver decapsulates with its private key and decrypts the ciphertext.
4. Record the operation result asserted by the test; do not treat this as a bare DH test or assume fixed ciphertext equality unless explicitly asserted. The testcase requires a sufficiently recent OpenSSL implementation and otherwise reports unsupported.

### Procedure: DSA/RSA key paths and ML-KEM

- **DSA/RSA key cases:** construct/import the requested key family, check operation status, and inspect the key-type or representation fields explicitly asserted by the source.
- **ML-KEM key support:** query/build the named ML-KEM key types and check key type and registration/inventory fields. This key-support test is separate from the full encapsulation/decapsulation and shared-secret equality flow in the PQC testcase.
- **Key-share vectors:** load the YAML group and client-share fields, decode the supplied share bytes, resolve the group, and invoke the key-exchange encapsulation path for supported ML-KEM/hybrid groups. Unknown groups, malformed fields, non-hybrid cases and unsupported OpenSSL versions are distinct non-success paths.

### Procedure: DSA and RSA key-specific cases

- **DSA:** construct/load the DSA key, check that the resolved key has DSA type, and compare the private-key bytes with the expected value where the source asserts them.
- **RSA:** construct the RSA key and run the testcase's encryption/decryption operations, recording their statuses. Do not infer a plaintext equality assertion unless the source compares the decrypted buffer.
- These are key-family-specific checks, separate from the broader generated-key identifier/NID inventory and the signature verification vectors.

### Procedure: key-exchange group matrix

1. The key-exchange testcase invokes its helper for the configured TLS groups, covering supported finite-field DH groups, named elliptic-curve groups, X25519/X448, and Brainpool variants.
2. Each helper constructs the relevant key-exchange inputs for the selected group and exercises the exchange path. Treat each group call as an independent case, subject to the active provider and group support.
3. The source also dispatches ML-KEM-512/768/1024 and selected hybrid groups such as P-256/ML-KEM-768, P-384/ML-KEM-1024 and X25519/ML-KEM-768.
4. Keep this broad group-exercise matrix separate from RFC 7748's fixed known-answer checks, and from YAML key-share encapsulation vectors. Check each helper's explicit assertions before claiming that every group compares a known shared-secret value.

### Procedure: RFC 7919 FFDHE parameter vectors

1. For each YAML row, decode the expected prime `p`, subgroup order `q` and generator `g`.
2. Resolve the matching FFDHE group parameters through the cryptographic implementation.
3. Compare the returned `p`, `q` and `g` with the vector fields.
4. The source also emits a key dump; that diagnostic output is not itself a parameter comparison.

### Procedure: optional FFDHE coverage

1. Run the executable with `-ffdhe` to invoke `testcase_key_ffdhe()` and `testcase_testvector_rfc7919()`. The fixed FFDHE-2048 case compares generated public/private bytes with expected values and exercises DH setup; the RFC 7919 YAML consumer is a separate vector path. Without the option both calls are skipped.

## 3. Evidence

### Source-level coverage

**1. Named key generation and inventory**

~~~text
request RSA / RSA-PSS / P-256 / X25519 / X448 / Ed25519 / Ed448
  -> crypto_keygen.gen()
  -> enumerate key objects by selected key ID
  -> assert expected IDs exist
  -> compare selected OpenSSL key-type NIDs
~~~

The source also builds a fixed X25519 key from coordinates. Printed key material is diagnostic; the inventory checks do not validate every generated parameter.

**2. DER and raw-key serialization**

~~~text
key object
  -> encode selected DER or raw public/private representation
  -> decode into a new key object
  -> check return status
  -> compare reconstructed objects / exact bytes only in cases
     with an explicit equality assertion
~~~

Successful encode/decode alone proves the operation completed, not that every byte or field is correct.

**3. DH / EC / key exchange**

~~~text
construct parameters and key pairs
  -> derive secret on side A
  -> derive secret on side B
  -> compare secret bytes where both results are asserted
~~~

Keep this agreement check distinct from tests that only generate keys or check operation status.

**4. Keygen and key-share YAML vectors**

~~~text
YAML row -> decode key material / group / algorithm fields
  -> construct key or key-share object
  -> run requested import/export/exchange operation
  -> compare only explicit expected fields, bytes or shared secrets
~~~

The concrete assertion is vector-specific; fixture presence does not establish every row or field is checked.

**5. FFDHE — optional**

~~~text
-ffdhe supplied?
  yes -> testcase_key_ffdhe() + testcase_testvector_rfc7919()
          -> run FFDHE key and RFC 7919 cases
  no  -> main dispatcher skips these calls
~~~

Unsupported algorithms/providers must be reported separately from positive key agreement. HPKE has its own encapsulation/context contract and should not be treated as interchangeable with a bare DH equality test.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation documentation: `sdk/crypto/basic/key/README.md`; curve taxonomy is preserved in `sdk/crypto/basic/README.md` under Developer Notes
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.

## 5. References

Source files in this directory:
- `test/testcase/crypto/key/testcase_crypto_key.cpp`
- `test/testcase/crypto/key/testcase_curves.cpp`
- `test/testcase/crypto/key/testcase_der.cpp`
- `test/testcase/crypto/key/testcase_dh.cpp`
- `test/testcase/crypto/key/testcase_ec.cpp`
- `test/testcase/crypto/key/testcase_hpke.cpp`
- `test/testcase/crypto/key/testcase_key_dsa.cpp`
- `test/testcase/crypto/key/testcase_key_ffdhe.cpp`
- `test/testcase/crypto/key/testcase_key_mlkem.cpp`
- `test/testcase/crypto/key/testcase_key_rsa.cpp`
- `test/testcase/crypto/key/testcase_keyexchange.cpp`
- `test/testcase/crypto/key/testcase_keygen.cpp`
- `test/testcase/crypto/key/testvector_keygen.cpp`
- `test/testcase/crypto/key/testvector_keyshare.cpp`
- `test/testcase/crypto/key/testvector_rfc7919.cpp`
