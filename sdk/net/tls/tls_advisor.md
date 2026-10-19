## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS advisor

## 1. Role

### Role

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

## 2. Model

### Resource groups

The source maintains resource tables for:

- TLS cipher suites
- AEAD parameters
- TLS parameters
- TLS extension values
- QUIC-related identifiers

The `resource_*.cpp` files contain the static mapping data, while the advisor classes provide lookup/query behavior.

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

### Related test

- `test/testcase/tls/testcase_resource.cpp`

## 5. Relationships

### Relationship with crypto advisor

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

## 6. References

### Related source

- `sdk/net/tls/advisor/tls_advisor.cpp`
- `sdk/net/tls/advisor/resource.cpp`
- `sdk/net/tls/advisor/resource_ciphersuite.cpp`
- `sdk/net/tls/advisor/resource_aead_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_extensiontype_values.cpp`
- `sdk/net/tls/advisor/resource_quic.cpp`
- `sdk/crypto/advisor/`
