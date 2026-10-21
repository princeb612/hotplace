## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS advisor

## 1. Role


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

## 2. Data Model

### Resource groups

The source maintains resource tables for:

- TLS cipher suites
- AEAD parameters
- TLS parameters
- TLS extension values
- QUIC-related identifiers

The `resource_*.cpp` files contain the static mapping data, while the advisor classes provide lookup/query behavior.

## 3. Behavior Model

The advisor performs lookup and conversion over static resource tables. A successful metadata lookup establishes that an identifier is recognized by the table, not that a provider can execute the corresponding cryptographic operation in every build. The crypto advisor performs a related but separate mapping from cryptographic identifiers to primitive/key/backend metadata.

## 4. Relationships



- `sdk/net/tls/advisor/tls_advisor.cpp`
- `sdk/net/tls/advisor/resource.cpp`
- `sdk/net/tls/advisor/resource_ciphersuite.cpp`
- `sdk/net/tls/advisor/resource_aead_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_parameters.cpp`
- `sdk/net/tls/advisor/resource_tls_extensiontype_values.cpp`
- `sdk/net/tls/advisor/resource_quic.cpp`
- `sdk/crypto/advisor/`
- [TLS/DTLS/QUIC overview](README.md)
- [TLS advisor directory](advisor/README.md)
- [TLS protection/session model](tls-protection-and-session.md)
- [TLS key schedule](protection/tls_key_schedule.md)
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

## 5. References

- [IANA TLS Parameters Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml)
- [IANA QUIC Transport Parameters and Error Codes](https://www.iana.org/assignments/quic/quic.xhtml)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
