# OQS Provider Adapter

`sdk/crypto/oqs` is a thin integration layer between OpenSSL 3's provider API and hotplace's crypto abstractions. The important design point is that hotplace does not contain an independent ML-KEM/Dilithium/Falcon/SPHINCS+ implementation here. The actual cryptographic implementation is supplied by `oqsprovider`.

## Context and provider discovery

`pqc_oqs::open()` creates a private `OSSL_LIB_CTX`, loads the OpenSSL default provider and `oqsprovider`, then queries `OSSL_OP_KEM` and `OSSL_OP_SIGNATURE`.

The discovered names are retained in `oqs_context`:

- a general algorithm-name map
- KEM algorithm list
- signature algorithm list
- flags indicating whether an OpenSSL NID/OID mapping is available

`close()` unloads both providers and frees the library context.

## Algorithm enumeration

`for_each()` exposes the discovered KEM and signature names to callers. This keeps provider-specific algorithm discovery separate from the actual cryptographic operations.

The OID flag is significant to the current tests: algorithms without an OpenSSL NID mapping are reported as unsupported by the OQS testcases rather than being treated as fully supported hotplace algorithms.

## Key and operation bridge

The adapter delegates most work to existing hotplace/OpenSSL helpers:

- `keygen()` → `crypto_keychain::pkey_keygen_byname()`
- `encode()` / `decode()` → `crypto_keychain` key serialization
- `encapsule()` / `decapsule()` → `openssl_pqc`
- `sign()` / `verify()` → `openssl_pqc`

This means the OQS layer is mainly responsible for provider selection and context management; key representation and cryptographic EVP operation details remain in `crypto/basic`.

## Supported operation shape

### KEM

```text
Alice: keygen
   ↓
public/private key
   ↓ public key
Bob: encapsulate
   ↓
capsule + shared secret
   ↓ capsule
Alice: decapsulate with private key
   ↓
shared secret
```

The KEM testcase compares Bob's and Alice's resulting shared secrets.

### Signature

```text
keygen
  ↓
private/public key
  ↓
sign(message, private key)
  ↓
signature
verify(message, public key, signature)
```

The DSA testcase exercises this path for each OID-registered provider signature algorithm.

## Version boundary

The implementation is guarded by `OPENSSL_VERSION_NUMBER >= 0x30000000L` because the provider architecture is an OpenSSL 3 API. Older OpenSSL builds return `not_supported` from the OQS adapter.

## External dependency

The provider itself is external:

- `oqs-provider` supplies the PQC algorithms.
- The test environment must make the provider module available to OpenSSL (`ossl-modules`).

The existing `test/testcase/crypto/oqs-provider.md` remains the place for provider-specific study notes and external test-vector work.
