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

# Crypto Testcases

## 1. What

This directory contains the `test-crypto` testcase executable and focused testcase groups for hotplace's cryptographic primitives and selected backend integrations. Its scope includes encryption and AEAD, hashes and MACs, key derivation, key generation and exchange, signatures, random-number facilities, and post-quantum cryptography.

The test suite mixes three kinds of evidence: fixed known-answer vectors, operation/result checks, and generated-key or round-trip flows. These are not interchangeable. A successful API return does not necessarily prove that output bytes match a known answer; generated-key success does not establish exhaustive algorithm interoperability; diagnostic output is not an expected-value assertion.

## 2. How

### 2.1 Prepare and run the crypto testcase executable

1. Start at `sample.cpp`; `sample.hpp` declares the testcase functions and shares command-line options, logger, and testcase reporter.
2. Parse options and configure logging. `-v` enables verbose output, `-l` writes `test.log`, `-t` adds timestamps, and `-k` enables key dumps only at call sites that consult it.
3. Call `openssl_startup()` before the cryptographic cases. The guarded cleanup path pairs this with `openssl_cleanup()`.
4. Dispatch the registered groups in source order: advisor; encryption/cipher vectors; digest/MAC/OTP/transcript hash; KDF; keys/exchanges; common PQC/OQS; random generation; signatures and certificate-related cases.
5. Flush logging, call `_test_case.report(5)`, and return `_test_case.result()`. The report covers functions reached by this executable under the active build/provider; it does not imply that every file in the directory ran.
6. Preserve the actual invocation, build options, OpenSSL version, and provider configuration when comparing reports.

### 2.2 Select optional test paths

1. Use `-s` to dispatch PBKDF2/RFC 6070 and scrypt/RFC 7914 cases; without it, those calls are skipped.
2. Use `-argon2` to dispatch RFC 9106 cases.
3. Use `-ffdhe` to dispatch the FFDHE key test and RFC 7919 vector consumer.
4. At build time, `SUPPORT_OQS` selects `pqc/oqs/*.cpp` or `pqc/dummy/*.cpp`. Compiling an OQS test does not guarantee that its provider loads or that an algorithm is available at runtime.
5. Debug/trace switches are registered only in `DEBUG` builds. Verbose and trace output helps diagnosis but does not itself add assertions.

### 2.3 Procedure: execute a YAML known-answer vector

The RFC 7539 consumer illustrates the common input → operation → expected-output pattern.

1. Load `testvector_rfc7539.yml` through `yaml_testcase`; read each item's algorithm, key, counter, IV, AAD, tag, plaintext, and ciphertext fields.
2. Decode the hexadecimal fields into byte buffers, convert plaintext to bytes, and derive the ChaCha20 nonce from the counter and IV.
3. Call `openssl_crypt::encrypt()` with the selected algorithm, key, nonce, plaintext, and AAD.
4. Compare produced ciphertext and authentication tag with the vector's expected values. Record the operation result separately.
5. Only if encryption succeeds, decrypt the supplied vector ciphertext using its tag and compare the recovered plaintext with the original input.
6. For `chacha20-poly1305`, also construct the TLS AEAD builder and compare its produced tag and ciphertext. The builder's decrypt branch checks operation status but does not explicitly compare recovered plaintext with the original.

Other consumers use different oracles; do not assume every vector performs all three kinds of checks.

### 2.4 Procedure: run the inline HKDF check

1. Begin the `hkdf` testcase and construct `openssl_kdf`.
2. Supply password `secret`, salt `salt`, info `label`, SHA-256, and output length 10.
3. Call `hmac_kdf()` to populate the result buffer.
4. Decode expected hex `2ac4369f525996f8de13` and compare the complete expected byte vector with the derived result.
5. Treat verbose dumps as diagnostics; byte equality is the known-answer assertion.

### 2.5 Interpret vector evidence and schema fields

1. Distinguish a successful status from an expected-output equality, two-party shared-secret equality, object equality, or printed value. They establish different properties.
2. Confirm that the source function is dispatched by `sample.cpp` and check option/build/provider conditions before claiming a fixture was executed.
3. Use the schema summary table below to locate the consumer for each schema identifier.
4. Use the corresponding YAML field contract to understand its input shape, but treat the consumer's field reads and assertions as authoritative. A field's presence in the schema does not prove every row or field is used.

### 2.6 Data-driven vector schema reference

These YAML formats are part of the procedures above: the consumer source determines which fields are decoded, which operations run, and which expected values are compared. The field map is a format reference, not evidence that every row or field is executed.

| Schema identifier | Primary consumer | Main fields and verification purpose |
|---|---|---|
| `CBC-HMAC JOSE` | `crypt/testvector_cbc_hmac_jose.cpp` | `encalg`, `macalg`, combined key `k`, plaintext `p`, IV `iv`, AAD `a`, CBC result `q`, intermediate `s`, tag `t`, combined ciphertext `c`; checks protocol-specific intermediate and final values. |
| `CBC-HMAC TLS` | `crypt/testvector_cbc_hmac_tls.cpp` | `flag` selects MAC-then-encrypt/encrypt-then-MAC; separate encryption/MAC keys, IV, AAD, plaintext and ciphertext. |
| `BLOCK CIPHERS` | `crypt/testvector_cavp_blockciphers.cpp` | Algorithm, key, IV, plaintext and expected ciphertext; vector encryption and plaintext recovery. |
| `RFC 3394` | `crypt/testvector_rfc3394.cpp` | AES key-wrap algorithm, KEK, key/key data; wrapped-key output and unwrap path. |
| `RFC 4615` | `kdf/testvector_rfc4615.cpp` | Salt, input key material and expected PRF output. |
| `CKDF` | KDF consumer in the corresponding testcase source | Salt, IKM, output length, info and expected OKM. |
| `RFC 5869` | `kdf/testvector_rfc5869.cpp` | Digest algorithm/length, IKM, salt, info, PRK and OKM; extract/expand expected values. |
| `RFC 7539` | `crypt/testvector_rfc7539.cpp` | ChaCha20/ChaCha20-Poly1305, key, counter, IV, optional AAD/tag, plaintext and ciphertext. |
| `RFC 7919` | `key/testvector_rfc7919.cpp` | FFDHE group and expected prime `p`, subgroup order `q`, generator `g`. |
| `ECDSA TESTVECTOR` | `sign/testvector_ecdsa.cpp` | Curve, message encoding, private/public key material, nonce `k`, signature components `r` and `s`; verifies supplied signatures. |
| `DSA PARAMETER` / `DSA TESTVECTOR` | `sign/testvector_dsa.cpp` | Named DSA parameters `p/q/g`; test rows reference parameters and provide algorithm, message, key and signature values. |
| `RSA KEY` / `RSA PKCS 1.5` / `RSA PSS` | `sign/testvector_rsassa.cpp` | RSA key fields `n/e/d`; signature cases reference a key and specify algorithm, message, signature and (for PSS) salt. |
| `CLIENT SHARE` | `key/testvector_keyshare.cpp` | Group and encoded client key-share bytes for encapsulation/key-share handling. |
| `KEY GEN` | `key/testvector_keygen.cpp` | Key type, identifier and algorithm-specific `param` members for EC/OKP/RSA/DH/DSA key material. |

#### YAML field contracts

#### YAML schema

* CBC-HMAC JOSE schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC JOSE   # [mandatory] "CBC-HMAC JOSE"
    items:
      - item: string
        encalg: string      # [mandatory] algorithm
        macalg: string      # [mandatory] algorithm
        k: hexstring        # [mandatory] mackey || enckey
        p: hexstring        # [mandatory] PT
        iv: hexstring       # [mandatory] IV
        a: hexstring        # [mandatory] AAD
        q: hexstring        # [mandatory] Q = CBC-ENC(ENC_KEY, P || PS)
        s: hexstring        # [mandatory] S = IV || Q
        t: hexstring        # [mandatory] T = MAC(MAC_KEY, A || S || AL)
        c: hexstring        # [mandatory] CT = S || T
````

* CBC-HMAC JOSE TLS schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC TLS    # [mandatory] "CBC-HMAC TLS"
    items:
      - item: string        #
        flag: string        # [mandatory] "mac_then_encrypt"|"encrypt_then_mac"
        enckey: hexstring   # [mandatory] key
        iv: hexstring       # [mandatory] IV
        macalg: string      # [mandatory] algorithm
        mackey: hexstring   # [mandatory] MAC key
        aad: hexstring      # [mandatory] AAD
        pt: hexstring       # [mandatory] plaintext
        ct: hexstring       # [mandatory] ciphertext
````

* NIST CAVP block-ciphers TLS schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: BLOCK CIPHERS       # [mandatory] "BLOCK CIPHERS"
    items:
      - item: string            #
        alg: string             # [mandatory] algorithm
        key: hexstring          # [mandatory] key
        iv: hexstring           # [mandatory] IV
        pt: hexstring           # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* RFC 3394 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 3394            # [mandatory] "RFC 3394"
    items:
      - item: string            #
        alg: string             # [mandatory] "aes-128-wrap"|"aes-192-wrap"|"aes-256-wrap"
        kek: hexstring          # [mandatory] key encryption key
        key: hexstring          # [mandatory] key
        keydata: hexstring      # [mandatory] key data
````

* RFC 4615 schema
  * RFC 4615 The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128 (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 4615            # [mandatory] "RFC 4615"
    items:
      - item: string            # [mandatory] 
        salt: hexstring         # [mandatory] key
        ikm: hexstring          # [mandatory] message
        prk: hexstring          # [mandatory] RFC 4493 AES-CMAC, RFC 4615 PRF output
````

* CKDF schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: CKDF                # [mandatory] CKDF
    items:
      - item: string            # [mandatory] 
        salt: hexstring         # [mandatory] key
        ikm: hexstring          # [mandatory] message
        prk: hexstring          # [mandatory] RFC 4493 AES-CMAC, RFC 4615 PRF output
        len: int                # [mandatory]
        info: hexstring         # [mandatory]
        okm: hexstring          # [mandatory]
````

* RFC 5869 schema
  * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 5869            # [mandatory] "RFC 5869"
    items:
      - item: string            # [mandatory] 
        alg: string             # [mandatory]
        dlen: int               # [mandatory]
        ikm: hexstring          # [mandatory]
        salt: hexstring         # [mandatory]
        info: hexstring         # [mandatory]
        prk: hexstring          # [mandatory]
        okm: hexstring          # [mandatory]
````

* RFC 7539 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 7539            # [mandatory] "RFC 7539"
    items:
      - item: string            # [mandatory] 
        alg: string             # [mandatory] "chacha20"|"chacha20-poly1305"
        key: hexstring          # [mandatory] key
        counter: int            # [mandatory] counter
        iv: hexstring           # [mandatory] IV
        aad: hexstring          # mandatory if chacha20-poly1305
        tag: hexstring          # mandatory if chacha20-poly1305
        pt: string              # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* RFC 7919 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 7919            # [mandatory] "RFC 7919"
    items:
      - item: string            #
        group: string           # [mandatory]
        p: hexstring            # [mandatory] p
        q: hexstring            # [mandatory] q
        g: hexstring            # [mandatory] g
````

* NIST CAVP ECDSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: ECDSA TESTVECTOR    # [mandatory] "ECDSA TESTVECTOR"
    encoding: "base16"|"plain"  # [mandatory] m encoding
    items:
      - item: string            #
        curve: string           # [mandatory]
        m: hexstring            # [mandatory] message (see encoding)
        d: hexstring            # [mandatory] private
        x: hexstring            # [mandatory] public
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP DSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: DSA PARAMETER       # [mandatory] "DSA PARAMETER"
    items:
      - item: string            # [mandatory] primary key
        p: hexstring            # [mandatory] prime
        q: hexstring            # [mandatory] subprime
        g: hexstring            # [mandatory] generator
  - example: string             # [mandatory] testcase
    schema: DSA TESTVECTOR      # [mandatory] "DSA TESTVECTOR"
    items:
      - item: string            #
        param: string           # [mandatory] foreign key (param) references DSA PARAMETER (item)
        alg: string             # [mandatory]
        m: hexstring            # [mandatory]
        x: hexstring            # [mandatory] private
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP RSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RSA KEY             # [mandatory] "RSA KEY"
    items:
      - item: string            # [mandatory] primary key
        n: hexstring            # [mandatory] modulus
        e: hexstring            # [mandatory] public exponent
        d: hexstring            # [mandatory] private exponent
  - example: string             # [mandatory] testcase
    schema: RSA PKCS 1.5        # [mandatory] "RSA PKCS 1.5"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
  - example: string             # [mandatory] testcase
    schema: RSA PSS             # [mandatory] "RSA PSS"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
        salt: hexstring         # [mandatory] salt
````

* CLIENT SHARE schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: CLIENT SHARE        # [mandatory] "CLIENT SHARE"
    items:
    - item: string              # [mandatory]
      group: string             # [mandatory]
      share: hexstring          # [mandatory]
````

* KEY GEN schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: KEY GEN             # [mandatory] "KEY GEN"
    items:
    - item: string              # [mandatory]
      kty: string               # [mandatory] rsaEncryption, RSASSA-PSS, X25519, Ed25519, P-256, P-384, P-521, DSA, ffdhe2048, ...
      kid: string               # [mandatory]
      param:                    #
        x: encoded              # DH, DSA, EC, OKP
        y: encoded              # DH, DSA, EC
        d: encoded              # EC, OKP, RSA
        n: encoded              # RSA
        e: encoded              # RSA
        p: encoded              # DH, DSA
        q: encoded              # DH, DSA
        g: encoded              # DH, DSA
        uncompressed: encoded   # EC
        ybit: bool              # EC
````
## 3. Evidence

### Source-level coverage

The crypto executable contains several different verification contracts. These diagrams separate known-answer checks, internal cross-checks, status-only checks, and paths that depend on runtime options or provider availability.

**1. Fixed-vector encryption / AEAD**

~~~text
RFC/CAVP YAML row
  -> decode key, nonce/IV, AAD, plaintext, expected ciphertext/tag
  -> construct algorithm-specific nonce / parameters
  -> encrypt
  -> compare ciphertext and tag with vector
  -> if operation succeeded:
       decrypt vector ciphertext with vector tag
       -> compare recovered plaintext with original
~~~

RFC 7539 explicitly compares ciphertext/tag. Its plaintext comparison follows the OpenSSL encryption success path. The separate AEAD-builder branch also compares ciphertext/tag, but its decrypt branch checks operation status without an explicit plaintext-equality assertion.

**2. Digest, MAC and OTP vectors**

~~~text
RFC 4231 key/message/expected digest
  -> decode hex inputs
  -> test_hash_routine(algorithm)
  -> compare digest bytes with expected digest

RFC 4226 secret + counter sequence
  -> generate 10 HOTP values
  -> compare complete uint32 sequence with expected array

RFC 4493 key + message vectors
  -> AES-CMAC calculation
  -> compare result bytes with expected tag

RFC 6238 key + timestamp/time-step vectors
  -> calculate TOTP for selected hash algorithms
  -> compare selected code values with expected values
~~~

Digest enumeration and successful initialization are not known-answer checks. These vector paths are only as broad as their listed inputs and expected arrays.

**3. KDF**

~~~text
inline HKDF:
  password/salt/info + SHA-256 + length 10
    -> hmac_kdf()
    -> compare output bytes with 2ac4369f525996f8de13

YAML HKDF/CMAC-KDF:
  -> load vector fields
  -> configure digest/PRF and output length
  -> derive
  -> compare derived bytes with expected output

PBKDF2 / scrypt -> only when -s
Argon2          -> only when -argon2
FFDHE vectors   -> only when -ffdhe
~~~

The option-controlled paths are not implied by a report from the default invocation.

**4. Key creation, representation and agreement**

~~~text
named key request -> generate -> check selected key IDs / key-type NIDs
key object -> DER/raw/JWK/CWK encode/decode
  -> status check
  -> object equality or exact-byte comparison only where asserted

two key pairs / key-share fixture
  -> derive or exchange
  -> compare both shared secrets where explicitly present
~~~

Key dumps and successful import/export do not independently prove every key parameter or byte representation.

**5. Signature and PQC paths**

~~~text
ECDSA YAML (curve/digest/message/key/r/s)
  -> assemble supplied R || S
  -> verify with OpenSSL API
  -> verify with crypto_sign builder API

sign/verify matrix
  -> sign selected message
  -> check success or expected failure
  -> verify produced signature where invoked
  -> compare ECDSA signature length for selected cases

ML-KEM (OpenSSL >= 3.5)
  -> key generation -> public-key encode/decode
  -> compare reconstructed public-key objects
  -> encapsulate / decapsulate
  -> compare shared-secret bytes

OQS source files -> built only with SUPPORT_OQS
  -> runtime checks also depend on provider and algorithm availability
~~~

ECDSA vector verification accepts a supplied signature; it does not compare a newly generated signature to the vector. A version guard or unsupported-provider result is not positive algorithm verification.

**6. Randomness helpers and advisor metadata**

~~~text
rand32 / nonce / token loops
  -> invoke API 30 times
  -> optional log
  -> record pre-initialized success status
  -> no output, uniqueness, or statistical comparison

advisor feature enumeration
  -> record selected feature availability statuses
  -> print registered inventory

curve aliases / cipher metadata
  -> lookup selected names
  -> compare expected NID / scheme and resource mappings
~~~

These checks concern API invocation or metadata consistency, not entropy quality or primitive correctness.

**Interpretation boundary**

A source file or YAML fixture being present is not evidence that its consumer was invoked. An operation status, expected-output comparison, object equality, shared-secret equality, and diagnostic log each establish different things. Keep the runtime report and its optional flags/provider configuration alongside any claim that a particular path ran.


### Documentation and runtime verification status

The supplied `test/testcase/crypto/report` records **4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv** entries. The [Test Report Snapshot](../test-report-status.md) associates the last known run with **Revision 1104 · MinGW64/GCC · CTest** based on conversation context. The report itself does not identify the tested source revision, exact compiler version, build flags, or all optional crypto flags. These totals remain historical runtime evidence, separate from this documentation's Revision 1106 source basis. No runtime tests were executed as part of this documentation update.

## 4. Relationships

- [Crypto implementation overview](../../../sdk/crypto/README.md) — module boundaries and backend/provider configuration.
- [Basic cryptographic primitives](../../../sdk/crypto/basic/README.md) — cipher, digest, KDF, key, MAC and signature implementations.
- `test/testcase/cose/` and `test/testcase/jose/` — format-specific cryptographic consumers, distinct from primitive known-answer tests.
- `test/testcase/tls/` — TLS-specific transcript, key-schedule and record-protection tests.
- `test/testcase/crypto/CMakeLists.txt` — source/vector collection, optional OQS versus dummy source selection, vector-file copying, and `test-crypto` target setup.

## 5. References

- [Test vectors and external references](test-vectors.md)
- [ECDSA curve/hash reference](ecdsa-curves.md)
- [Post-quantum cryptography](pqc.md)
- [oqs-provider](oqs-provider.md)
- `test/testcase/crypto/sample.cpp`
- `test/testcase/crypto/sample.hpp`
- `test/testcase/crypto/kdf/testcase_hkdf.cpp`
- `test/testcase/crypto/crypt/testvector_rfc7539.cpp`
- `test/testcase/crypto/hash/testcase_rfc4231.cpp`
- `test/testcase/crypto/key/testcase_keygen.cpp`
- `test/testcase/crypto/sign/testvector_ecdsa.cpp`
- `test/testcase/crypto/pqc/testcase_pqc_kem.cpp`
- `test/testcase/crypto/prng/testcase_random.cpp`
