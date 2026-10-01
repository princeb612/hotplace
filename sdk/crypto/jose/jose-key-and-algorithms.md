# JWK and JOSE algorithm mapping

## JWK

`json_web_key` is the bridge between JSON Web Key material and hotplace's `crypto_key` abstraction.

The current implementation handles the main JWK families:

- `oct` — symmetric keys
- `RSA`
- `EC` — P-256, P-384 and P-521
- `OKP` — Ed25519, Ed448, X25519 and X448

The implementation supports reading JSON key material and writing the corresponding representation. The test suite also exercises JWK/PEM interoperability and the RFC 7638 thumbprint examples.

The important boundary is:

```text
JWK JSON
   ↓
json_web_key
   ↓
crypto_key
   ↓
crypto/basic
```

## Algorithm identifiers

`types.hpp` groups JOSE identifiers into protocol roles:

- `jws_t` — JWS signature/MAC algorithms
- `jwa_t` — JWE key-management algorithms
- `jwe_t` — JWE content-encryption algorithms
- `jwa_group_t` / related metadata — algorithm families

The JOSE implementation uses these identifiers to select the cryptographic path rather than scattering string comparisons throughout the implementation.

## Algorithm mapping

The current implementation covers the major RFC 7518 families used by the source:

```text
JWS
 ├── HS256/384/512
 ├── RS256/384/512
 ├── PS256/384/512
 ├── ES256/384/512
 └── EdDSA

JWE key management
 ├── RSA1_5 / RSA-OAEP variants
 ├── A128/192/256KW
 ├── dir
 ├── ECDH-ES and ECDH-ES+KW
 ├── A128/192/256GCMKW
 └── PBES2-HS*+A*KW

JWE content encryption
 ├── A128/192/256CBC-HS*
 └── A128/192/256GCM
```

The exact implementation status and historical TODOs remain documented in the existing source README; this document records the architectural mapping rather than duplicating the full status table.

## Relationship to advisor

`crypto/advisor` provides common algorithm/resource metadata. JOSE adds the protocol-specific identifier layer and parameter rules required by JWS/JWE/JWK.

```text
crypto/advisor
      ↓
JOSE identifier / protocol metadata
      ↓
JWS / JWE processing
      ↓
crypto/basic
```

## Tests and references

The primary test directory is `test/testcase/jose/`. Important coverage includes RFC 7515/7516/7517/7518, RFC 7520 examples, RFC 7638 thumbprints and RFC 8037 algorithms, plus the current AKP/ML-DSA vectors.
