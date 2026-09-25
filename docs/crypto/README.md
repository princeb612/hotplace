# Cryptography — Algorithms, Keys, Operations & Protocol Adapters

## Context

`sdk/crypto` is the cryptographic foundation used by several higher-level parts of hotplace. It is not itself a protocol such as TLS, JOSE, or COSE. Its role is to turn cryptographic meaning into reusable operations, key representations, algorithm selection, and provider-backed execution.

The important boundary is therefore:

```text
                 protocol / security object
             ┌──────────┬──────────┬──────────┐
             │   TLS    │   JOSE   │   COSE   │
             └────┬─────┴────┬─────┴────┬─────┘
                  │          │          │
                  └──────────┼──────────┘
                             ▼
                        sdk/crypto
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
      key material       crypto operation    algorithm meaning
          │                  │                  │
       key/keygen       encrypt/hash/MAC/   advisor/types
       keychain         sign/KDF/exchange
          │                  │
          └──────────┬───────┘
                     ▼
               OpenSSL / OQS
```

The same primitive can consequently appear in different protocol contexts without making the primitive implementation responsible for the protocol semantics.

### Reading Path

A first reading of the crypto area is easiest if it follows a requirement from a
consumer protocol down to a reusable operation, then back up to the protocol that
gives the result its meaning:

```text
TLS / COSE / JOSE requirement
          ↓
algorithm and key selection
          ↓
crypto operation / key material
          ↓
provider-backed execution
          ↓
protocol-specific result and state
```

This keeps two questions separate: **what cryptographic capability is needed?**
and **what does the protocol do with the result?** The first question belongs to
`crypto`; the second remains with TLS, COSE, JOSE, or another consumer.

For a reader, this boundary is easiest to follow by asking two questions: **what
cryptographic operation is required, and which protocol gives that operation its
meaning and state?** The first question belongs here; the second belongs to TLS,
COSE, JOSE, or another consumer.

## History

The cryptographic area grew together with the protocols that consumed it. The CHANGELOG provides several useful checkpoints:

- Revision 108: CBOR was introduced; this became the encoding foundation used later by COSE.
- Revision 211: COSE RFC examples were added, establishing concrete COSE security-object experiments.
- Revision 442: COSE became a broader implemented feature across RFC 8152 and related registrations.
- Revision 702: DSA testing appears as an explicit cryptographic checkpoint.
- Revisions 729–790: TLS/DTLS work exercised certificates, key exchange, CBC, GCM, CCM, ECDSA, and related cryptographic operations.
- Revision 770: OpenSSL 3.5 was applied and subsequently used by the TLS/DTLS work.
- Revisions 883–889: OQS-provider KEM/DSA and PQC KEM testing established the post-quantum branch.
- Revisions 890–902: ML-KEM parameter sets and hybrid TLS groups were tested, including X25519MLKEM768 and SecP256r1MLKEM768/SecP384r1MLKEM1024.
- Revision 953: TLS 1.3 ML-DSA certificate testing was recorded.
- Revision 998: ML-DSA was tested for JOSE and COSE.
- Revision 999: SLH-DSA in TLS 1.3 became a study item.
- Revision 1020: `crypto_keygen` was added as an explicit key-generation facility.

This history shows the role of `sdk/crypto` more clearly than a directory listing: protocol studies repeatedly exposed a reusable cryptographic requirement, which then became a shared operation, key representation, algorithm mapping, or provider integration.

## Conceptual

### Cryptography is organized by operation, not by protocol

The central operations are:

```text
key material
   │
   ├── generate / import / extract / select
   │
   ├── key agreement / KEM
   │
   └── describe / encode / resolve

message material
   │
   ├── hash / transcript hash
   ├── MAC
   ├── sign / verify
   └── encrypt / decrypt / AEAD

secret material
   │
   └── KDF / key schedule input
```

This gives TLS, JOSE, and COSE a common vocabulary while preserving their different protocol rules.

### Key material and cryptographic operation are separate

A key is not an algorithm invocation. The project reflects this distinction through `crypto_key_object`, `crypto_key`, `crypto_keychain`, `crypto_keygen`, `crypto_keyexchange`, and the operation classes such as `crypto_hash`, `crypto_hmac`, `crypto_sign`, `crypto_encrypt`, and `crypto_aead`.

A useful model is:

```text
             key description
          kid / alg / use / group
                    │
                    ▼
              crypto_key
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      key selection       key material
          │                   │
          └─────────┬─────────┘
                    ▼
             crypto operation
```

This is particularly important for JOSE and COSE, where a serialized key has protocol-level metadata (`kid`, algorithm, use/key operations) in addition to the mathematical key material.

### Operation families

| Family | Meaning | Representative hotplace area |
|---|---|---|
| Hash | one-way digest / transcript input | `crypto_hash`, `transcript_hash` |
| MAC | symmetric authentication/integrity | `crypto_hmac`, CBC-HMAC |
| AEAD / encryption | confidentiality plus authenticated integrity | `crypto_aead`, `crypto_encrypt` |
| Signature | asymmetric authentication of a message | `crypto_sign` |
| Key agreement / KEM | establish shared secret material | `crypto_keyexchange` |
| KDF | derive usable keys from secret/input material | `basic/kdf` |
| Key management | create, store, select, import/export key material | `crypto_keygen`, `crypto_key`, `crypto_keychain` |
| PRNG / OTP | randomness and application authentication primitives | `basic/prng`, OTP classes |
| Algorithm metadata | translate protocol names/IDs to crypto meanings | `crypto_advisor`, `types.hpp` |

The categories are related, but they are not interchangeable. In particular, a KEM is a key-establishment mechanism, not an encryption primitive; a signature authenticates data, not a TLS record; a hash is an input to many larger constructions but is not itself a MAC or signature.

### Algorithm meaning is a shared vocabulary

`crypto_advisor` and the common type definitions provide mappings among several naming systems: internal crypto types, TLS groups/signature schemes, JOSE algorithms, COSE algorithms, curves, key types, and cryptographic categories.

That makes the advisor layer different from the primitive implementation layer:

```text
protocol identifier
       │
       ▼
 crypto_advisor / types
       │
       ├── what algorithm is this?
       ├── what key type does it require?
       ├── what operation category is it?
       └── how does another protocol name the same construction?
       │
       ▼
 basic crypto operation
```

The current source explicitly includes ML-KEM, ML-DSA, and SLH-DSA key types/signature categories alongside RSA, EC, OKP, DH, HMAC, and conventional signature schemes.

## Structural

### Layered structure

The current `sdk/crypto` tree can be read as several layers rather than as one flat collection of algorithms:

```text
sdk/crypto
│
├── basic/                 reusable cryptographic operations
│   ├── crypt/             cipher / AEAD implementations
│   ├── digest/            hash / transcript hash
│   ├── kdf/               key derivation
│   ├── key/               key containers, keychain, keygen, exchange
│   ├── mac/               HMAC / CBC-HMAC / OTP
│   ├── pqc/               provider-facing PQC support
│   ├── prng/              random generation
│   └── sign/              signature implementations
│
├── advisor/               algorithm and protocol identifier mapping
├── jose/                  JOSE security objects
├── cose/                  COSE security objects
├── oqs/                   OQS-provider integration
└── authenticode/          certificate/signature verification application
```

`basic` is the reusable operation layer. `jose` and `cose` are security-object layers that consume those operations. `advisor` connects protocol-level algorithm identifiers to the operation/key vocabulary. `oqs` and the PQC-specific basic code connect post-quantum algorithms to the provider-backed execution path.

### Key layer

The key area is broader than simply storing a private key.

```text
                 crypto_keygen
                      │
                      ▼
                 key material
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   crypto_key     keychain       extraction
        │             │             │
        └─────────────┼─────────────┘
                      ▼
               crypto_key_object
                      │
               EVP_PKEY / X509
```

`keydesc` carries selection metadata such as `kid`, algorithm, use, and group. `crypto_key` acts as a key collection/selection boundary, while `crypto_keychain` supplies concrete representations and conversion paths for RSA, EC/OKP, DH, DSA, symmetric keys, and the PQC key families represented by the project.

### Operation layer

The operation classes form the reusable substrate consumed by higher layers:

```text
                       crypto operation
                             │
       ┌──────────┬──────────┼───────────┬───────────┐
       ▼          ▼          ▼           ▼           ▼
      hash       MAC       encrypt      sign       KDF
       │          │          │           │           │
   SHA family   HMAC/     AES/AEAD    RSA/ECDSA/  HKDF/PBKDF2/
                CMAC      ChaCha20    EdDSA/ML-DSA  scrypt/Argon2
```

The implementations are largely provider-backed through OpenSSL, while the project-specific interfaces preserve a stable operation model above the provider API.

### Advisor layer

The advisor is a semantic bridge rather than another crypto algorithm implementation. It maintains mappings for TLS signature schemes/groups, JOSE algorithms, COSE algorithms, curves, key types, and related cryptographic metadata.

A particularly useful relationship is the common signature vocabulary:

```text
TLS signature scheme ─┐
JOSE JWS algorithm ───┼──► advisor ─► signature_t / key type / hash
COSE algorithm ───────┘
```

This is why the same underlying ECDSA, EdDSA, RSA, or ML-DSA implementation can participate in several protocol stacks without duplicating the primitive implementation.

### JOSE boundary

JOSE provides JSON-oriented security objects and algorithm/key registries. Its source area contains JWS/JWE/JWK-oriented classes. The cryptographic boundary is:

```text
JWS / JWE / JWK
      │
      ├── protected/header semantics
      ├── compact / JSON serialization
      └── algorithm selection
               │
               ▼
          sdk/crypto/basic
```

The JOSE layer decides what must be signed or encrypted and how the result is represented. `sdk/crypto/basic` performs the underlying cryptographic operation.

### COSE boundary

COSE is the CBOR-oriented counterpart. Its source area contains signing, encryption, MAC, recipient, key, and countersignature structures. The boundary is:

```text
COSE message
   │
   ├── protected / unprotected headers
   ├── payload / ciphertext
   ├── recipient / countersignature
   └── algorithm semantics
             │
             ▼
        sdk/crypto/basic
```

COSE therefore adds protocol/object semantics around the same broad operation families: sign, MAC, encrypt, and key distribution.

### TLS boundary

TLS uses `sdk/crypto` differently from JOSE/COSE. TLS is a stateful transport security protocol and composes cryptographic primitives into a handshake, transcript, key schedule, record protection, and authentication flow.

```text
TLS session
    │
    ├── handshake / transcript
    ├── key schedule / KDF
    ├── authentication / signature
    ├── key exchange / KEM
    └── record protection / AEAD
              │
              ▼
         sdk/crypto/basic
```

The crypto layer does not own TLS handshake state. It supplies the operations and key material that TLS orchestrates.

## PQC and the cryptographic layer

### PQC fits naturally at the operation boundary

The current source already separates PQC concerns according to cryptographic role rather than treating “PQC” as one algorithm family:

```text
PQC
├── ML-KEM      key establishment / KEM
├── ML-DSA      digital signature
└── SLH-DSA     digital signature
```

The project also has an OQS-provider integration area and OpenSSL PQC integration. This is important because the higher protocols do not need to know how a provider exposes the primitive; they need a key type and an operation with the required semantics.

### ML-KEM path

```text
ML-KEM key material
       │
       ▼
 crypto_key / key exchange
       │
       ▼
 shared secret
       │
       ├── TLS 1.3 key schedule
       └── other KEM-consuming constructions
```

In TLS, ML-KEM participates in key establishment. The project has tested ML-KEM-512/768/1024 and hybrid groups such as X25519MLKEM768 and SecP256r1MLKEM768/SecP384r1MLKEM1024. The hybrid-group semantics belong to TLS; the KEM operation itself belongs here.

### ML-DSA / SLH-DSA path

```text
message / transcript
        │
        ▼
   crypto_sign
        │
   ┌────┴─────┐
   ▼          ▼
ML-DSA     SLH-DSA
   │          │
   ├── TLS authentication
   ├── JOSE signature
   └── COSE signature
```

This illustrates an important project-level relationship: one signature implementation can be exercised by different higher-level protocols. The protocol determines the signed input, algorithm identifier, key representation, and wire/object encoding; the crypto layer performs the signature operation.

### PQC is not a separate architecture

The useful architectural interpretation is therefore:

```text
                    security protocol
          ┌────────────┼────────────┐
          ▼            ▼            ▼
         TLS          JOSE         COSE
          │            │            │
          └────────────┼────────────┘
                       ▼
                 operation layer
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
    classical         hybrid            PQC
    RSA/EC/OKP      X25519+ML-KEM     ML-KEM
                                     ML-DSA
                                     SLH-DSA
```

PQC is consequently a change in available key/operation families, not a replacement for the protocol layers above it.

## Flow

### Generic cryptographic operation

```text
protocol/security object
        │
        ▼
 algorithm identifier
        │
        ▼
 crypto_advisor / type mapping
        │
        ▼
 key selection / key material
        │
        ▼
 operation object
        │
        ▼
 OpenSSL / OQS provider
        │
        ▼
 cryptographic result
        │
        ▼
 protocol-specific encoding/state transition
```

### TLS example

```text
TLS ClientHello / ServerHello
          │
          ▼
   select group / signature
          │
          ▼
     sdk/crypto
      ├─ KEM/ECDH
      ├─ signature
      ├─ transcript hash
      └─ HKDF / AEAD
          │
          ▼
      TLS key schedule
          │
          ▼
      protected records
```

For QUIC, the same TLS handshake cryptography is consumed by the QUIC packet layer, but QUIC packet protection and TLS record framing remain distinct responsibilities.

### JOSE / COSE example

```text
JWS / COSE_Sign1
       │
       ▼
 protected signing input
       │
       ▼
 algorithm + key resolution
       │
       ▼
    crypto_sign
       │
       ▼
 signature bytes
       │
       ▼
 JOSE / COSE object encoding
```

The inverse verification path resolves the key and algorithm, reconstructs the protocol-specific signing input, and then invokes the same verification-capable cryptographic operation.

## Study & Verification

The crypto area is verified through both primitive-level and protocol-level experiments.

### Primitive and key tests

The `basic` area contains tests and implementations for ciphers, AEAD, digests, HMAC/CMAC, KDFs, key generation, key exchange, signatures, and key representations. The project also records OpenSSL-based validation and compatibility work.

### TLS verification

TLS RFC traces and protocol tests exercise the crypto layer in a larger state machine: TLS 1.2/1.3 ciphersuites, transcript hashes, Finished, CertificateVerify, key exchange, AEAD/CBC protection, and PQC/hybrid groups.

### JOSE / COSE verification

JOSE and COSE RFC examples exercise the same cryptographic operations through different security-object encodings. The project explicitly recorded ML-DSA testing for both JOSE and COSE at Revision 998.

### PQC verification

The PQC path has been tested through OQS-provider KEM/DSA support and OpenSSL 3.5-based KEM integration. The TLS-specific tests then validate the same primitives inside a protocol context, including ML-KEM hybrid groups and ML-DSA authentication.

The important verification chain is:

```text
primitive test
     ↓
key / operation test
     ↓
protocol construction test
     ↓
interoperability / RFC vector
     ↓
PCAP / capture-replay where applicable
```

A failure at a higher layer therefore does not automatically imply a primitive failure; the layers have different contracts.

## Status

At Revision 1090, `sdk/crypto` is a substantial shared cryptographic substrate rather than an isolated algorithm collection. The later ASN.1/parser work does not change this ownership boundary; ASN.1 schema semantics remain outside the crypto layer.

Implemented/used areas include:

- symmetric encryption and AEAD, including AES families and ChaCha20-Poly1305;
- digest, HMAC, and CMAC operations;
- KDFs including HKDF, PBKDF2, scrypt, and Argon2 variants;
- RSA, EC/OKP, DH/DSA and related key representations;
- ECDH/key exchange and key generation;
- RSA/ECDSA/EdDSA and PQC signatures including ML-DSA and SLH-DSA support paths;
- ML-KEM and hybrid KEM integration paths;
- JOSE JWS/JWE/JWK/JWA integration;
- COSE signing, MAC, encryption, recipients, keys, and countersignatures;
- TLS/DTLS/QUIC cryptographic integration through the higher-level protocol layers;
- OQS/OpenSSL provider-backed PQC integration.

The most important structural conclusion is that `sdk/crypto` should be read as the **operation and key substrate**, while TLS, JOSE, and COSE remain the owners of their own protocol/security-object semantics.

## Related Documents

- [TLS](../tls/README.md) — handshake, transcript, key schedule, record protection, and transport integration
- [COSE / JOSE](../cose_jose/README.md) — security-object semantics and protocol-specific signing/encryption/key representations
- [QUIC](../quic/README.md) — packet/frame/stream processing and TLS integration
- [Payload](../io/payload/README.md) — generic binary field layout and encoding substrate
- [Network Server](../network_server/README.md) — I/O, session, protocol detection, framing, and dispatch
