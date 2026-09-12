# COSE / JOSE — CBOR, JSON, Keys & Key Exchange

**Edition 1 · Revision 1078**

## Context

COSE and JOSE occupy a similar role in `hotplace`: they define application-level security objects for signing, MAC, encryption, and key representation, while using different serialization ecosystems.

```text
                         Security Objects
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
               COSE                       JOSE
          CBOR-based                    JSON-based
                 │                         │
                 ▼                         ▼
               CBOR                      JSON
                 │                         │
                 └────────────┬────────────┘
                              │
                     crypto abstraction
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
        crypto_key      crypto_keychain   crypto_keygen
                                                │
                                                ▼
                                      crypto_keyexchange
                                         ├── ECDH
                                         └── KEM
```

The important relationship is not that COSE and JOSE share one wire format. They share a **security-object problem space** and rely on common cryptographic key infrastructure.

## History

The `CHANGELOG.md` gives a particularly clear history for the CBOR/COSE side.

- Revision 107 — CBOR feature based on RFC 7049 and RFC 8949.
- Revision 211 — COSE RFC 8152 examples were added as `.cbor` and `.diag` material.
- Revision 411 — COSE recipient handling was changed for the RFC 8152 Appendix B two-layer recipient structure.
- Revision 442 — COSE feature work was expanded across RFC 8152, 8230, 8392, 8812, 9052, 9053, and 9338, with valgrind verification.
- Revision 926 — CBOR/COSE refactoring was tested.
- Revision 998 — ML-DSA was tested for both JOSE and COSE.
- Revision 1020 — `crypto_keygen` was added.

The changelog does not provide a dedicated milestone for the initial JOSE implementation, so this document does not invent one. Current source and testcase structure are used to describe the present relationship instead.

## Conceptual

### COSE and JOSE are parallel layers

The two families solve closely related application problems:

| Concern | COSE | JOSE |
|---|---|---|
| Object serialization | CBOR | JSON |
| Signed object | COSE Sign / Sign1 | JWS |
| Encrypted object | COSE Encrypt / Encrypt0 | JWE |
| MAC | COSE Mac / Mac0 | JWS/MAC algorithms |
| Key representation | COSE_Key | JWK |
| Nested processing | Sign/Encrypt structures | JWS + JWE nesting |

The parallel should therefore be drawn at the **semantic layer**, not by claiming that one is a serialization wrapper around the other.

### Security object → cryptographic operation

Both layers eventually reach the same kind of cryptographic primitives:

```text
application payload
      │
      ▼
security object
      │
      ├── signing ──────► signature
      ├── MAC ──────────► authentication tag
      └── encryption ───► ciphertext
                │
                ▼
             key use
                │
                ▼
          crypto_key / keychain
```

The object layer owns representation and protocol semantics. The crypto layer owns key material and primitive operations.

## Structural

### COSE

The COSE implementation is centered around message structures rather than one monolithic class.

```text
cose_composer
     │
     ├── protected / unprotected
     ├── payload
     ├── recipients
     └── countersigns
            │
            ▼
      COSE message
            │
   ┌────────┼────────┐
   ▼        ▼        ▼
 Encrypt   Sign      MAC
```

Important structural pieces include:

- `cose_protected` / `cose_unprotected`
- `cose_recipient` / `cose_recipients`
- `cose_countersign` / `cose_countersigns`
- `cose_composer`
- `cbor_object_encryption`
- `cbor_object_signing`
- `cbor_object_signing_encryption`
- `cose_key` / `cbor_web_key`

The message classes describe the COSE structure, while the cryptographic operation classes perform signing, MAC, and encryption work.

### JOSE

JOSE follows the same semantic decomposition using JSON-oriented objects:

```text
json_object_signing
json_object_encryption
json_object_signing_encryption
          │
          ├── headers
          ├── payload
          └── key
               │
               ▼
         json_web_key
```

Current implementation areas include:

- `json_object_signing`
- `json_object_signing_composer`
- `json_object_encryption`
- `json_object_encryption_composer`
- `json_object_signing_encryption`
- `json_web_key`
- `json_web_signature`

The composer classes are the construction boundary; the object classes represent the resulting JOSE operations.

### Common key infrastructure

The key abstraction sits below both COSE and JOSE.

```text
                 crypto_key
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
    crypto_keychain       crypto_keygen
          │                   │
          │             generate/import
          │                   │
          └─────────┬─────────┘
                    ▼
             key representation
                    │
                    ▼
           COSE Key / JWK
```

`crypto_key` represents the cryptographic key object. `crypto_keychain` provides key storage/lookup and algorithm-specific handling. `crypto_keygen` creates key material.

This separation matters because a COSE Key or JWK is not itself the underlying cryptographic key object. It is a standard representation used by the protocol layer.

### Key exchange

`crypto_keyexchange` is another layer below COSE/JOSE and is especially relevant to recipient/key-management algorithms.

```text
peer public share
       │
       ▼
crypto_keyexchange
       │
 ┌─────┴──────────┐
 ▼                ▼
ECDH              KEM
 │                │
 ▼                ▼
shared secret   encapsulation
                / decapsulation
       │
       ▼
 key-management result
```

The current implementation exposes `keygen`, `exchange`, `encaps`, and `decaps`.

The same abstraction is used for classical ECDH/ECDHE-style agreement and ML-KEM-based operations, including hybrid groups used by the TLS-related crypto infrastructure.

## Flow

### COSE

A typical signing/encryption path is:

```text
payload
  │
  ▼
COSE composer
  │
  ├── protected header
  ├── unprotected header
  ├── payload
  └── recipient / countersign
  │
  ▼
cryptographic operation
  │
  ▼
CBOR encoding
  │
  ▼
COSE message
```

For multi-recipient encryption, recipient objects form a hierarchy instead of flattening all key-management information into the top-level message.

### JOSE

A corresponding JOSE path is:

```text
payload
  │
  ▼
JWS / JWE composer
  │
  ├── alg
  ├── enc
  ├── kid
  └── key
  │
  ▼
cryptographic operation
  │
  ▼
JSON serialization
  │
  ▼
JWS / JWE
```

Nested signing and encryption are represented by `json_object_signing_encryption`.

### Key representation and operation are separate

```text
JWK / COSE_Key
       │
       ▼
parse / map
       │
       ▼
crypto_key
       │
       ├── sign / verify
       ├── encrypt / decrypt
       └── key exchange
```

This is the key structural connection between the protocol objects and the lower crypto infrastructure.

## Study & Verification

### COSE RFC examples

The COSE testcase contains the original COSE examples in `.cbor` / `.diag` form and a YAML regression representation derived from the COSE working-group example collection.

The current testcase source explicitly identifies:

```text
https://github.com/cose-wg/Examples
```

as the source of the example collection.

The verification flow is:

```text
COSE Examples
     │
     ▼
example files
     │
     ▼
YAML regression vector
     │
     ▼
testvector_cose_examples.cpp
     │
     ▼
parse / compose / verify
     │
     ▼
test_case
```

The YAML schema records keys and message inputs separately from the COSE item, allowing a test item to refer to its key set and carry additional shared/derived cryptographic values.

This turns an external reference collection into a repeatable local regression mechanism rather than a one-time manual interoperability check.

### COSE RFC test coverage

The testcase tree includes verification for:

- RFC 8152
- RFC 8392
- RFC 8778
- RFC 9338
- COSE working-group examples
- algorithm/key resources and related AKP test vectors

The current source also contains ML-DSA AKP vectors for 44, 65, and 87 parameter sets.

### JOSE RFC test coverage

The JOSE testcase tree contains dedicated RFC-oriented tests for:

```text
RFC 7515  JWS
RFC 7516  JWE
RFC 7517  JWK
RFC 7518  JWA
RFC 7520  JOSE examples
RFC 7638  JWK Thumbprint
RFC 8037  CFRG curves / OKP
```

It also carries concrete JWK, JWS, and JWE example files rather than testing only generated values.

### Key and key-exchange verification

The crypto testcase area includes direct tests of:

```text
testcase_crypto_key
testcase_keyexchange
```

and the COSE/JOSE testcases repeatedly use `crypto_keychain` to construct or resolve keys.

This creates a useful verification chain:

```text
standard example
      │
      ▼
COSE / JOSE object
      │
      ▼
key representation
      │
      ▼
crypto_key / crypto_keychain
      │
      ▼
cryptographic operation
      │
      ▼
test_case
```

### Regression is the important part

The value of these tests is not only RFC conformance. They preserve concrete combinations of:

- serialization
- headers
- keys
- algorithms
- recipient structures
- signatures/MACs
- ciphertext
- expected results

as reusable regression inputs.

That makes the testcase tree a second layer of documentation for the implementation.

## Status

As of Revision 1078:

- CBOR is an established lower serialization layer.
- COSE is implemented as a structured security-object layer over CBOR.
- JOSE provides the corresponding JSON-oriented security-object layer.
- COSE has a substantial RFC/example regression corpus.
- JOSE has RFC-specific JWS/JWE/JWK test material and example files.
- `crypto_key`, `crypto_keychain`, and `crypto_keygen` provide shared key representation, management, and generation infrastructure.
- `crypto_keyexchange` provides ECDH and KEM-oriented key exchange operations.
- ML-DSA is exercised in both JOSE and COSE paths.
- The project therefore has a clear separation between **wire/object representation**, **key representation**, and **cryptographic operation**.

The useful mental model is:

```text
                 COSE                    JOSE
                   │                       │
                 CBOR                    JSON
                   │                       │
                   └──────────┬────────────┘
                              │
                     security semantics
                              │
                              ▼
                         key objects
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
          crypto_key     keychain        keygen
                              │
                              ▼
                       key exchange
                         ECDH / KEM
```

The two protocol families are therefore best documented side-by-side, while keeping their distinct serialization and standard-specific structures explicit.
