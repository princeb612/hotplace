## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# OQS provider adapter — implementation details

## 1. Role

This document describes the boundary between hotplace and the external OpenSSL `oqsprovider` module.

## 2. Model

The adapter keeps provider discovery separate from operations. `pqc_oqs::open()` creates a library context, loads the default provider and OQS provider, then queries KEM and signature operation names. The resulting `oqs_context` retains the discovered names and whether NID/OID mapping is available.

The main bridge operations are:

- `keygen()` → `crypto_keychain::pkey_keygen_byname()`
- `encode()` / `decode()` → key serialization helpers
- `encapsule()` / `decapsule()` → `openssl_pqc`
- `sign()` / `verify()` → `openssl_pqc`

## 3. Important behavior and lifetime

Provider handles and the library context have an explicit lifetime. `close()` unloads providers and frees the context. The adapter is conditional on OpenSSL 3; a provider module must also be installed where OpenSSL can load it.

Algorithm discovery is not equivalent to uniform support: the existing tests gate full operation attempts on `oqs_alg_oid_registered`, and classify other enumerated entries as `not_supported`.

## 4. Example from the source tests

The KEM test compares the shared secret produced by encapsulation with the secret recovered by decapsulation. The signature test signs with a private key and verifies with the public key. These validate the integrated provider path, not a full independent mathematical implementation.

## 5. Relationships

```text
provider discovery → key abstraction → EVP-backed operation
        OQS         crypto_keychain      openssl_pqc
```

See [OQS tests](oqs-tests.md) for source coverage and limitations.

## 6. References

- `oqs.hpp`, `oqs.cpp`, `types.hpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_encode.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_kem.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_dsa.cpp`
