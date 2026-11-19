## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# OQS provider adapter — implementation details

## 1. Role

This document describes the boundary between hotplace and the external OpenSSL `oqsprovider` module.

## 2. Data Model
The adapter keeps provider discovery separate from operations. `SUPPORT_OQS` controls whether these SDK sources are included in the crypto target. `pqc_oqs::open()` creates a library context, loads the default provider and OQS provider, then queries KEM and signature operation names. The resulting `oqs_context` retains the discovered names and whether `OBJ_sn2nid()` can map each name to an NID/OID.

The main bridge operations are:

- `keygen()` → `crypto_keychain::pkey_keygen_byname()`
- `encode()` / `decode()` → key serialization helpers
- `encapsule()` / `decapsule()` → `openssl_pqc`
- `sign()` / `verify()` → `openssl_pqc`

## 3. Behavior Model
Provider handles and the library context have an explicit lifetime. `close()` unloads providers and frees the context. The adapter is conditional on OpenSSL 3; a provider module must also be installed where OpenSSL can load it. `for_each()` supports only `OSSL_OP_KEM` and `OSSL_OP_SIGNATURE`; other operation identifiers return `not_supported`.

Algorithm discovery is not equivalent to uniform support: the existing tests gate full operation attempts on `oqs_alg_oid_registered`, and classify other enumerated entries as `not_supported`.

**Current open-path limitations:** `open()` checks whether `oqsprovider` loaded but does not check `OSSL_LIB_CTX_new()` or the default-provider load result. Its null-output-pointer branch sets `invalid_parameter` but does not exit before the later `*context` assignment, so a null output pointer can still be dereferenced if provider loading succeeds. Pass a valid output pointer; this path should be fixed before being treated as safe validation.

## 4. Relationships
### Source-test evidence

The encode test checks PEM/DER public/private and encrypted-private serialization statuses for OID-registered algorithms but does not compare reconstructed key objects. The KEM test compares the shared secret produced by encapsulation with the secret recovered by decapsulation; it does not decode the encoded private key. The signature test signs with a private key and verifies with the public key. These validate selected integrated provider paths, not a full independent mathematical implementation or cross-provider conformance.

```text
provider discovery → key abstraction → EVP-backed operation
        OQS         crypto_keychain      openssl_pqc
```

See [OQS tests](oqs-tests.md) for source coverage and limitations.

- `oqs.hpp`, `oqs.cpp`, `types.hpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_encode.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_kem.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_dsa.cpp`
