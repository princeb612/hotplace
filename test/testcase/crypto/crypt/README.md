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
# Encryption and AEAD Testcases

## 1. What

This directory contains test sources for encryption and aead in hotplace. The category covers public-key encryption, authenticated encryption, cipher modes, and vector-backed paths.

## 2. How

### Procedure: run a generic cipher builder case

1. Select the algorithm and mode supplied by the test and ask `cipher_encrypt_builder` to construct the cipher.
2. Pass the test key, IV and input bytes to `encrypt()`; record the operation status and any output dump.
3. Where the case invokes `decrypt()`, feed it the ciphertext and record that status too.
4. Do not infer plaintext round-trip equality from successful encrypt/decrypt statuses or printed buffers: these generic builder cases primarily report operation status unless a separate explicit comparison is present.

### Procedure: exercise the generic AEAD builder and CCM cases

1. Prepare the fixed sample plaintext, key, IV and AAD from the testcase.
2. Resolve the requested AEAD scheme through the builder; the CCM test also varies AES-128/192/256-CCM schemes and constructs the nonce required by the operation.
3. Invoke encryption, then decryption with the returned ciphertext and tag.
4. Inspect the recorded operation statuses. Treat these builder/CCM cases as API-path checks; they are not the same as fixed-vector tag/ciphertext comparisons in the RFC/YAML consumers.

### Procedure: RSA public-key encryption/decryption

1. Construct an RSA key from the Base64URL-encoded modulus, public exponent and private exponent fields used by the testcase, then add it to the `crypto_keychain`.
2. Resolve the key object and exercise the supported public-key encryption mode(s) selected by the testcase.
3. Decrypt the resulting ciphertext with the corresponding private-key operation and record each operation status.
4. This is a generated ciphertext round-trip path. Unless the source explicitly compares the recovered plaintext to the original, a successful decrypt status should not be documented as a byte-for-byte equality assertion.

### Procedure: OpenSSL cipher mode and buffer-size exercise

1. The generic `openssl_crypt` routine opens a cipher context for the selected algorithm/mode, key and IV.
2. Exercise the listed modes (CBC, CFB, CFB1, CFB8, OFB, ECB, CTR, GCM and CCM) when available in the active OpenSSL build.
3. Run the routine with both a repeated large-stream workload (10 iterations of 4096 units) and the zero-delay/speed-oriented path.
4. For authenticated modes, pass AAD and tag through the encrypt/decrypt APIs. The routine reports operation status; its large-stream comment explicitly describes checking error occurrence rather than benchmarking or asserting throughput.
5. Treat provider/algorithm unavailability and mode-specific support as environmental conditions, not as successful cipher verification.

### Procedure: NIST CAVP block-cipher vectors

1. Load each row from `testvector_cavp_blockciphers.yml`, including algorithm, key, IV, plaintext and expected ciphertext.
2. Decode the hexadecimal fields and open the `openssl_crypt` context for the selected algorithm/key/IV.
3. Encrypt the supplied plaintext and compare the resulting ciphertext byte-for-byte with the expected ciphertext.
4. Decrypt the vector's expected ciphertext and compare the recovered plaintext byte-for-byte with the supplied plaintext.
5. Keep these two byte comparisons separate: successful context setup alone is not a known-answer pass.

### Procedure: RFC 7539 ChaCha20 / ChaCha20-Poly1305

1. The YAML loader opens `testvector_rfc7539.yml` and visits each item. It extracts the algorithm, key, counter, IV, AAD, tag, plaintext and ciphertext.
2. Decode key, IV, AAD, tag and ciphertext from hex; convert the plaintext field to bytes. Use the counter and IV to build the ChaCha20 nonce with `openssl_chacha20_iv()`.
3. Invoke `openssl_crypt::encrypt()` using the YAML algorithm, decoded key/nonce, plaintext and AAD.
4. If encryption succeeds, compare both the returned tag and ciphertext with the vector values.
5. If the encryption result is successful, decrypt the vector's expected ciphertext using the expected tag and assert that recovered plaintext equals the original.
6. For `chacha20-poly1305`, separately build `tls_chacha20_poly1305`, encrypt again, and compare the builder's tag and ciphertext. The builder decrypt branch checks operation status and logs plaintext but does not explicitly assert plaintext equality.

### Procedure: RFC 3394 key wrapping

1. Load each YAML row's algorithm, key-encryption key (KEK), key material and expected wrapped-key bytes.
2. Decode the fields and invoke the RFC 3394 wrap/unwrap helper for the selected wrapping algorithm.
3. Compare the produced wrapped-key output with the vector's expected wrapped-key value. The helper also performs the unwrap operation; inspect its explicit assertions rather than assuming every intermediate buffer is compared.
4. Keep key wrapping separate from ordinary block encryption: the input to the wrapping operation is key material, and the output has the RFC 3394 wrapping format.

### Procedure: CBC-HMAC JOSE and TLS vectors

- **JOSE:** the YAML consumer reads the algorithm, encryption/MAC keys, IV, plaintext and expected intermediate/final fields. It checks the CBC-derived `S`, authentication value `T`, and combined `C` against the fixture, then checks encryption output and decrypted plaintext against expected values.
- **TLS 1.2:** each fixture specifies the MAC algorithm, encryption key, IV, MAC key, AAD, plaintext, ciphertext and ordering flag. The flag selects `mac_then_encrypt` or `encrypt_then_mac`; the test decrypts the supplied ciphertext and compares plaintext, then encrypts and exercises a second decrypt/round-trip comparison.
- These are protocol-specific composition paths, not interchangeable generic AEAD vectors.

### Procedure: follow an unlisted cipher fixture

1. For each remaining source, identify its own input contract and oracle before summarizing it. Decode the fields, configure the selected operation, and document whether the source checks exact output bytes, recovered plaintext, authentication/tag values, or only operation status. Diagnostic dumps are not assertions.

## 3. Evidence

### Source-level coverage

**1. RFC 7539 YAML vector — OpenSSL encryption path**

~~~text
YAML item
  -> read alg/key/counter/IV/AAD/tag/plaintext/ciphertext
  -> hex-decode binary fields
  -> derive ChaCha20 nonce from counter + IV
  -> openssl_crypt.encrypt()
  -> compare ciphertext == expected ciphertext
  -> compare tag == expected tag
  -> if encryption succeeded:
       openssl_crypt.decrypt(expected ciphertext, expected tag)
       -> assert recovered plaintext == original plaintext
~~~

The plaintext assertion is conditional on the preceding encryption result. The encryption vector check compares both ciphertext and tag; the operation-status record is separate.

**2. ChaCha20-Poly1305 AEAD builder path**

~~~text
algorithm == "chacha20-poly1305"
  -> build TLS ChaCha20-Poly1305 AEAD
  -> encrypt vector plaintext
  -> assert generated tag == expected tag
  -> assert generated ciphertext == expected ciphertext
  -> record encrypt status
  -> decrypt vector ciphertext
  -> record decrypt status
~~~

The builder branch logs decrypted plaintext but does **not** explicitly compare that plaintext with the original in this source. Do not infer plaintext round-trip equality from its decrypt status or dump.

**3. Other cipher / wrapping paths**

~~~text
CAVP block-cipher / RFC 3394 / JOSE CBC-HMAC / TLS CBC-HMAC
  -> load each consumer's input fixture
  -> decode/configure algorithm-specific parameters
  -> run encrypt/decrypt or wrap/unwrap
  -> verify only fields explicitly compared by that consumer
~~~

The exact oracle varies by source file. A successful return code is not a known-answer check unless output bytes/tag are compared. YAML file presence alone does not prove every row was loaded or asserted.

**4. Negative paths**

~~~text
invalid input / invalid tag / unsupported algorithm
  -> invoke operation
  -> compare returned status with expected rejection
~~~

Count a negative case only where the source asserts the expected rejection. Verbose output and intermediate dumps are diagnostic.


### Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The shared [Test Report Snapshot](../../test-report-status.md) associates the last known run with Revision 1104 · MinGW64/GCC · CTest based on conversation context; the report itself does not identify the tested source revision or full build configuration. This is historical runtime evidence, separate from the Revision 1106 documentation basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- Implementation documentation: `sdk/crypto/basic/crypt/README.md`; cipher inventory is preserved in `sdk/crypto/basic/README.md` under Developer Notes
- Parent testcase overview: `test/testcase/crypto/README.md`
- The parent testcase CMake configuration controls registration and build integration.
- Test implementation files: `test/testcase/crypto/crypt/testcase_aead_ccm.cpp`, `test/testcase/crypto/crypt/testcase_cipher_encrypt.cpp`, `test/testcase/crypto/crypt/testcase_crypto_aead.cpp`, `test/testcase/crypto/crypt/testcase_crypto_encrypt.cpp`, `test/testcase/crypto/crypt/testcase_openssl_crypt.cpp`, `test/testcase/crypto/crypt/testvector_cavp_blockciphers.cpp`, `test/testcase/crypto/crypt/testvector_cbc_hmac_jose.cpp`, `test/testcase/crypto/crypt/testvector_cbc_hmac_tls.cpp`, `test/testcase/crypto/crypt/testvector_rfc3394.cpp`, `test/testcase/crypto/crypt/testvector_rfc7539.cpp`

## 5. References
