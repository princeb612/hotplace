## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Key Derivation Functions

## 1. Role

The KDF layer provides several algorithms because “derive key material” covers different inputs and threat models. Password-hardening functions make guessing expensive; HKDF expands existing key material into purpose-specific secrets; AES-CMAC KDF serves a block-cipher-MAC-based derivation family; TLS label helpers encode protocol-specific context. These functions are not interchangeable just because they all return bytes.

## 2. Data Model

| Function family | Inputs and model | Appropriate role / distinction |
|---|---|---|
| HKDF | Hash algorithm, input keying material (IKM), salt, context/info, output length; extract and expand can be called separately | General-purpose expansion of existing key material. Salt and `info` separate extraction and application-specific outputs; it is not a password-hardening function. |
| PBKDF2 | Password, salt, iteration count, PRF/hash, output length | Password-based derivation with configurable iteration cost; compatibility-oriented and tested against RFC 6070 vectors. |
| scrypt | Password, salt, output length, `N`, `r`, `p` | Password-based derivation with memory-hard cost parameters. |
| Argon2 | Password, salt, optional associated data/secret, variant, iteration/memory/parallelism costs, output length | Memory-hard password hashing/derivation. The current implementation path is conditional on sufficiently new OpenSSL support; source comments specify OpenSSL 3.2 or newer. |
| AES-CMAC KDF (`ckdf`) | AES algorithm, IKM, salt, info, output length; CMAC-based extract/expand helpers | CMAC-based derivation for uses requiring this construction rather than HMAC-based HKDF. |
| TLS label derivation | Secret, output length, protocol label, context; TLS 1.3 and DTLS 1.3 label helpers | Encodes protocol-defined label/context structure around HKDF expansion. It is a primitive helper, not a complete TLS key schedule. |

### Main API grouping

```text
openssl_kdf
 ├─ hkdf / hmac_kdf
 │   ├─ hmac_kdf_extract
 │   └─ hkdf_expand
 ├─ pbkdf2
 ├─ scrypt
 ├─ argon2
 ├─ ckdf / cmac_kdf
 └─ hkdf_expand_label
     ├─ hkdf_expand_tls13_label
     └─ hkdf_expand_dtls13_label
```

## 3. Behavior Model

Algorithm-specific parameters are part of the security contract:

- PBKDF2's iteration count determines repeated PRF work; the caller must choose a suitable deployment cost.
- scrypt's `N`, `r`, and `p` affect work and memory profile.
- Argon2's variant and iteration, memory, and parallelism costs must be selected deliberately. Build/provider support is conditional, so source presence alone is not a runtime-availability guarantee.
- HKDF's output length, salt, and info must match the consuming protocol/application. `info` provides context separation; it does not create entropy.
- TLS label helpers serialize protocol labels and context according to the TLS/DTLS-specific path. The handshake/key-schedule state machine remains in `sdk/net/tls`.

A KDF does not generate random salts or nonces, store passwords, or manage key lifetime. Password KDFs should not be substituted for HKDF, and HKDF should not be treated as a password-hardening function.

## 4. Relationships

- `../../advisor/README.md` resolves digest names used by HMAC/HKDF and backend operations.
- `../digest/README.md` provides digest primitives used by digest-based KDFs.
- `../key/README.md` documents key objects that may consume derived bytes in key/session workflows.
- `sdk/net/tls/` owns protocol key-schedule sequencing; this module supplies derivation operations and TLS label helpers.
- `sdk/crypto/cose/` may use KDFs in COSE key agreement/distribution processing, while COSE owns the message-level context.

### Implementation entry points

- `openssl_kdf.cpp` — HKDF/HMAC-KDF and CMAC-KDF helpers.
- `openssl_kdf_pbkdf2.cpp`, `openssl_kdf_scrypt.cpp`, `openssl_kdf_argon.cpp`
- `openssl_kdf_aes.cpp`, `openssl_kdf_tls.cpp`
- `test/testcase/crypto/kdf/`

### Source-test evidence

- `testcase_hkdf.cpp` passes password bytes, salt bytes, the context string `label`, SHA-256 and a 10-byte output length to `openssl_kdf::hmac_kdf`. It compares the result with the fixed hexadecimal expectation `2ac4369f525996f8de13`.
- `testcase_rfc6070.cpp` covers PBKDF2; `testcase_rfc7914.cpp` covers scrypt; `testcase_rfc9106.cpp` covers Argon2; `testvector_rfc4615.cpp` covers AES-CMAC-related material.
- These vector/testcase files show source-level coverage, not runtime execution or availability in every build.

## 5. References

- RFC 4615 — The Advanced Encryption Standard-Cipher-based Message Authentication Code-PRF-128 (AES-CMAC-PRF-128).
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 6070 — PKCS #5: PBKDF2 Test Vectors.
- RFC 7914 — The scrypt Password-Based Key Derivation Function.
- RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.
- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
