# TLS advisor

## Role

`sdk/net/tls/advisor` is the identifier and parameter lookup layer for TLS, DTLS and QUIC. It does not implement the cryptographic primitives themselves.

Its purpose is to translate protocol identifiers into metadata used by the implementation.

```text
TLS / DTLS / QUIC identifier
          │
          ▼
     tls_advisor
          │
   ┌──────┼────────┬──────────┐
   ▼      ▼        ▼          ▼
cipher  AEAD     extension   QUIC/TLS
suite   params   values     parameters
          │
          ▼
      sdk/crypto
```

## Resource groups

The source maintains resource tables for:

- TLS cipher suites
- AEAD parameters
- TLS parameters
- TLS extension values
- QUIC-related identifiers

The `resource_*.cpp` files contain the static mapping data, while the advisor classes provide lookup/query behavior.

## Relationship with crypto advisor

TLS advisor and crypto advisor have different responsibilities:

```text
TLS protocol name / ID
        │
        ▼
   tls_advisor
        │
        ▼
crypto meaning / parameter
        │
        ▼
sdk/crypto/advisor
        │
        ▼
crypto operation / key type
```

The two advisor areas therefore form a vocabulary bridge between protocol-level identifiers and the reusable cryptographic implementation.

## Related source

- `sdk/net/tls/advisor/tls_advisor.cpp`
- `sdk/net/tls/advisor/resource.cpp`
- `sdk/net/tls/advisor/resource_ciphersuite.cpp`
- `sdk/net/tls/advisor/resource_aead_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_extensiontype_values.cpp`
- `sdk/net/tls/advisor/resource_quic.cpp`
- `sdk/crypto/advisor/`

## Related test

- `test/testcase/tls/testcase_resource.cpp`
