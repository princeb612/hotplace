## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ Documentation scope: implementation navigation│
└──────────────────────────────────────────────┘
```

# OQS provider adapter

## 1. Role

`sdk/crypto/oqs` (without the leading space) is the adapter between OpenSSL 3's provider API and hotplace's post-quantum crypto abstractions. It discovers provider-exposed KEM and signature algorithms and delegates key and operation work; it is not an independent implementation of the algorithms.

## 2. Data Model
The main API is `pqc_oqs`, with provider state represented by `oqs_context` in `types.hpp`. The adapter opens an isolated `OSSL_LIB_CTX`, loads the OpenSSL default provider and `oqsprovider`, then queries `OSSL_OP_KEM` and `OSSL_OP_SIGNATURE`.

```text
OSSL_LIB_CTX
   ├── default provider
   └── oqsprovider
         ├── KEM algorithm names
         └── SIGNATURE algorithm names
                   ↓
                pqc_oqs
```

The `oqs_alg_oid_registered` flag records whether an algorithm can be mapped through OpenSSL's NID/OID machinery. This is a capability boundary used by the current tests, not a guarantee that every algorithm exposed by the provider is fully usable through every hotplace path.

## 3. Behavior Model
`pqc_oqs::open()` initializes provider state; `for_each()` enumerates discovered names and flags; `close()` unloads the providers and releases the library context. Callers should close a successfully opened context and should not treat the context or provider handles as process-global stateless data.

The adapter delegates key generation and serialization to `crypto_keychain`, and KEM/signature operations to the common OpenSSL PQC helpers. The implementation is guarded for OpenSSL 3 provider APIs; older OpenSSL versions return `not_supported`.

## 4. Relationships
- `../basic/` provides common key, serialization, and crypto operations.
- `../advisor/` provides algorithm and OID-related metadata.
- `../../../test/testcase/crypto/pqc/` contains provider-backed and common PQC tests.
- `../../../test/testcase/crypto/oqs-provider.md` retains provider study notes and planned external-vector work.

### Implementation and source entry points

- `oqs.hpp`, `oqs.cpp`, `types.hpp`
- `oqs-provider-adapter.md`
- `oqs-tests.md`

### Test evidence and source entry points

`testcase_oqs_kem.cpp` checks a key-encapsulation round trip: key generation, public/private key encode/decode, encapsulation, decapsulation, and comparison of the two shared secrets. `testcase_oqs_dsa.cpp` checks signing and verification for OID-registered signature algorithms. See [the testcase map](../../../test/testcase/crypto/pqc/testcase_pqc.md).

- OpenSSL 3 provider API documentation
