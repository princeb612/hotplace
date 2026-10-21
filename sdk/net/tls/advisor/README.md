## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS/QUIC algorithm and parameter advisor

## 1. Role

`tls_advisor` is a lookup/resource provider for TLS, DTLS and QUIC identifiers and their implementation metadata. It exposes hint structures to callers so handshake, record protection and packet code can resolve a negotiated identifier into parameters; it does not itself execute cryptographic algorithms or advance handshake state.

## 2. Data Model

### Hint families

| Hint/resource family | Data represented | Typical consumer |
|---|---|---|
| Cipher-suite hint | TLS cipher-suite identifier and its mapped algorithm/parameter choices | Negotiation and protection setup |
| AEAD parameter hint | AEAD identifier and key/IV/tag-related parameters | Record/packet protection |
| TLS extension-type hint | Extension numeric value and recognized type metadata | ClientHello/ServerHello extension processing |
| TLS parameter hint | TLS protocol parameters and related enum/value metadata | Handshake/session processing |
| QUIC hint/resource | QUIC versions and QUIC-specific parameter/identifier metadata | QUIC session and packet path |

The concrete hint structure is not the same thing as a crypto implementation object. It is metadata used to choose/configure an operation. The TLS advisor coordinates with `sdk/crypto/advisor` for primitive-level information such as ciphers, hashes, curves, and signatures.

## 3. Behavior Model

A typical lookup path is:

```text
wire identifier / negotiated choice
  -> tls_advisor lookup
  -> matching hint (or no result)
  -> caller reads mapped parameters
  -> caller configures handshake, protection, or QUIC behavior
```

The caller must handle missing hints and unsupported operations. A known numeric identifier or populated hint does not prove that the selected algorithm is enabled in the current build or that a complete protocol path is implemented.

The advisor's tables are split across resource source files by family. This keeps identifier metadata centralized while session and protection code retain responsibility for timing, negotiation policy, state transitions, and cryptographic execution.

## 4. Relationships

- `tls_advisor.cpp`, `tls_advisor_aead_parameters.cpp`, `tls_advisor_quic.cpp`.
- `tls_advisor_tls_extensiontype_values.cpp`, `tls_advisor_tls_parameters.cpp`.
- `resource.cpp`, `resource_aead_parameters.cpp`, `resource_ciphersuite.cpp`, `resource_quic.cpp`, `resource_tls_extensiontype_values.cpp`, `resource_tls_parameters.cpp`.
- `sdk/crypto/advisor/` — primitive, key, curve, signature and algorithm metadata.
- [TLS protection](../protection/README.md) — consumes negotiated parameters for key schedule and protection.
- [TLS session support](../session/README.md) — handshake/session state.
- [QUIC](../quic/README.md) — QUIC packet/frame and session integration.
- [TLS overview](../README.md).

## 5. References

No external references are currently listed.
