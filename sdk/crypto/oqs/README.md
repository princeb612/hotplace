## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 2 · Revision 1107                     │
│ Documented with GPT-6                         │
│ Source basis: Revision 1107                   │
│ Documentation scope: implementation navigation│
└───────────────────────────────────────────────┘
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

### 3.1 Open a provider context and discover operations

```text
pqc_oqs::open(&context)
        |
        v
create isolated OSSL_LIB_CTX
        |
        +--> load "default" provider
        |
        +--> load "oqsprovider"
        |
        v
query provider operations
  OSSL_OP_KEM       -> context.kemalgs
  OSSL_OP_SIGNATURE -> context.sigalgs
        |
        v
for_each(context, opid, callback)
        |
        v
caller chooses an algorithm and checks its flags
        |
        v
pqc_oqs::close(context)
  unload providers + free library context
```

The algorithm lists are discovered from the provider at runtime. The adapter records whether each name maps to an OpenSSL NID/OID, but the flag is only one capability gate used by the current tests; it does not establish support for every key encoding or higher-level protocol. A successfully opened context owns provider handles and an `OSSL_LIB_CTX`, so close it after the operation sequence. On OpenSSL versions before 3.0, these methods return `not_supported`.

### 3.2 Concrete KEM caller path from `testcase_oqs_kem.cpp`

```text
open provider context
  -> enumerate OSSL_OP_KEM algorithms
  -> keep algorithms with oqs_alg_oid_registered
  -> keygen(algorithm)
  -> encode public key as DER
  -> decode DER public key as a separate EVP_PKEY
  -> encapsulate(decoded public key)
       -> capsule + Bob shared secret
  -> decapsulate(original private key, capsule)
       -> Alice shared secret
  -> assert Alice secret == Bob secret
  -> free EVP_PKEY objects
  -> close provider context
```

The testcase compares the two derived shared-secret buffers, which is stronger than checking only that encapsulation and decapsulation returned success. The capsule is the value sent to the private-key holder; it is not the shared secret. The test also encodes the private key for diagnostics/serialization exercise, but decapsulation uses the original in-memory key object. The loop treats algorithms without registered OIDs as `not_supported`; it does not test every provider-listed algorithm.

### 3.3 Concrete signature caller path from `testcase_oqs_dsa.cpp`

```text
open provider context
  -> enumerate OSSL_OP_SIGNATURE algorithms
  -> keep algorithms with oqs_alg_oid_registered
  -> keygen -> DER public-key encode/decode
  -> sign(message, private key) -> signature
  -> verify(message, decoded public key, signature)
  -> free EVP_PKEY objects
  -> close provider context
```

This source checks sign/verify statuses for the same message and signature; it is not a fixed signature-byte vector and does not mutate the message/signature to demonstrate rejection cases.

The adapter delegates key generation and serialization to `crypto_keychain`, and KEM/signature operations to the common OpenSSL PQC helpers. Provider discovery, algorithm naming, OID registration and successful cryptographic operations are separate conditions; none alone guarantees interoperability with a different provider or protocol.

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
