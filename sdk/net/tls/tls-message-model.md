## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS message model

## 1. Role


`sdk/net/tls/tls` is the wire-message model for TLS and DTLS. It separates the three major protocol objects used by the implementation:

```text
TLS / DTLS
   │
   ├── record
   │     └── carries handshake / alert / application data
   │
   ├── handshake
   │     └── ClientHello / ServerHello / Certificate / Finished ...
   │
   └── extension
         └── SNI / ALPN / key_share / PSK / supported_versions ...
```

The classes are primarily responsible for representing, encoding and decoding protocol messages. Cryptographic state is handled by `protection/`, while session-level sequencing and transport integration are handled by `session/` and the surrounding network layer.

## 2. Data Model

### Representation layers

~~~text
Wire/transport representations
  TLS  -> tls_record / tls_records
  DTLS -> DTLS records + handshake-fragment metadata
  QUIC -> QUIC packets / frames, including CRYPTO data

Logical message representation
  tls_handshake(s)
    ├─ handshake type + body length
    ├─ message-specific fields
    └─ tls_extensions (where defined)
         ├─ extension type
         └─ extension-specific payload
~~~

- **Record objects** represent content type, protocol version, record length, and record content. Content may be handshake, alert, application data, or ChangeCipherSpec; not every record contains a handshake.
- **Handshake objects** represent a typed message and its fields. A tls_handshakes collection is a message-level grouping; it is not equivalent to a record collection because record boundaries and handshake boundaries can differ.
- **Extension objects** represent typed negotiation values nested in messages that permit extensions. The extension type selects the interpretation of its payload; the advisor supplies identifier metadata, while the extension class owns payload encoding/decoding.
- **DTLS handshake fragments** add message-sequence, fragment-offset, and fragment-length information around a slice of the original handshake body. Fragmentation is not a new TLS handshake type; it is the DTLS transport representation of an existing handshake message.
- **QUIC CRYPTO frames** carry TLS handshake bytes but are not tls_record objects. QUIC's packet/frame model owns transport framing for those bytes.

### Important intermediate data

| Representation | Owner | Meaning / boundary |
|---|---|---|
| Typed handshake fields and extension collection | Message-specific handshake and extension objects | Logical message state; distinct from encoded bytes |
| Serialized handshake bytes | Handshake writer / collection | Encoded message representation that can be carried by TLS records, DTLS fragments, or QUIC CRYPTO data |
| Transcript bytes/digest | Protection layer | Protocol-defined handshake input and digest/checkpoint state |
| Negotiated version/cipher suite/group | `protection_context` and `tls_protection` | Selected protocol parameters, distinct from the original offers |
| Record/fragment layout | Record builder or DTLS publisher | Record or fragment representation, distinct from transport delivery |
| QUIC frame layout | QUIC frame objects / packet publisher | Encoded frame representation, distinct from packet protection and UDP delivery |

These are different representations of the same handshake progression. Do not assume an in-memory handshake object, serialized handshake bytes, a protected TLS record, and a QUIC CRYPTO frame are interchangeable.

## 3. Behavior Model

### Receive path

1. **Frame the incoming wire unit.** TLS reads record headers and declared lengths from the stream; DTLS works from datagram boundaries and DTLS record headers. The framing layer must establish available record content before interpreting it.
2. **Apply protection where required.** The record/protection path selects the directional key/IV and sequence context, authenticates/decrypts protected content, and returns plaintext content for parsing. Failure prevents plaintext from being treated as a successfully decoded message.
3. **Dispatch by content type.** Handshake content is passed to the handshake collection/parser; alert, application-data, and ChangeCipherSpec content use their own record representations.
4. **Dispatch each handshake by type.** The handshake builder/collection selects a message-specific class. That class decodes its fields and, where applicable, delegates extension payloads to extension-specific classes.
5. **Apply state separately.** The decoded object supplies message data; tls_session and tls_protection determine handshake stage, transcript updates, negotiation decisions, and the next protection state. Parsing a Finished or ServerHello object alone does not perform every state transition implied by the protocol.

### Send path

1. Construct message-specific handshake fields and any applicable extension objects.
2. Serialize the handshake message and its handshake header.
3. Select the wire boundary: ordinary TLS record construction, DTLS handshake fragmentation/record publication, or QUIC CRYPTO-frame construction.
4. For TLS/DTLS, apply the corresponding record protection and record framing; for QUIC, let the QUIC packet path frame/protect the packet using TLS-derived secrets.
5. Deliver serialized output through the selected container/callback to transport integration.

### Boundary conditions

A handshake message may span record boundaries, and a record may carry multiple handshake messages. DTLS can fragment handshake messages and receive records out of order. QUIC carries TLS handshake bytes in CRYPTO frames and uses QUIC packet-number spaces and packet protection. Those differences belong to the session/transport path even though the underlying TLS handshake types overlap.

## 5. Relationships

- [TLS/DTLS/QUIC overview](README.md) — directory-level protocol and transport model.
- [Record model](tls/record/README.md) — record header/body framing and content dispatch.
- [Handshake model](tls/handshake/README.md) — typed handshake objects and their read/write lifecycle.
- [Extension model](tls/extension/README.md) — nested extension envelopes and typed payloads.
- [TLS protection](protection/README.md) — transcript processing, key schedule, and record protection.
- [TLS session](session/README.md) — directional handshake state and transport-specific helpers.
- [TLS protection/session model](tls-protection-and-session.md) — cross-layer state and lifecycle.
- [TLS advisor](advisor/README.md) — protocol identifier and parameter lookup.
- [QUIC integration](quic/README.md) — TLS handshake bytes carried in CRYPTO frames.
- `test/testcase/tls/` — construction, alert, HelloRetryRequest, and TLS 1.2/1.3 source examples.

## 6. References

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147)
