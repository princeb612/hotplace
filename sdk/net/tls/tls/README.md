## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS message layers

## 1. Role

This directory groups the three core TLS message representations: records, handshake messages, and extensions. They are related but distinct layers. Records provide transport framing, handshake messages represent negotiation units, and extensions carry typed negotiation parameters within applicable handshake messages.

## 2. Data Model

```text
transport bytes
  -> [record]
       -> record fragment
            -> [handshake message]
                 -> type-specific fields
                 -> extension list (where defined)
                      -> extension type + payload
```

The relationship is not a one-to-one nesting in every case: a record can carry non-handshake content, and handshake messages may span record boundaries. Extension parsing is scoped to the message and protocol version that contains it.

## 3. Behavior Model

Incoming bytes are framed into records, protected content is authenticated/decrypted as required, and handshake bytes are parsed into typed messages. The session/handshake logic then applies state and role rules; extension handlers interpret the typed extension payloads. Outgoing data follows the reverse conceptual direction, but session state decides which messages and extensions are legal at each stage.

QUIC reuses TLS 1.3 handshake semantics but does not use ordinary TLS records for its handshake transport. QUIC carries handshake bytes in CRYPTO frames and has separate packet/frame processing.

## 5. Relationships

- [Record layer](record/README.md) — record header, content and framing boundary.
- [Handshake messages](handshake/README.md) — message types and structured fields.
- [Extensions](extension/README.md) — typed extension payloads and negotiation parameters.
- [TLS advisor](../advisor/README.md) — type/hint metadata.
- [TLS protection](../protection/README.md) — transcript hashing, key schedule and record protection.
- [TLS session support](../session/README.md) — handshake state and protocol lifecycle.
- [QUIC integration](../quic/README.md) — CRYPTO-frame transport of TLS handshake bytes.

## 6. References

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
