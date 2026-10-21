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

# TLS record

## 1. Role

The record layer provides the wire envelope used to carry TLS content over a byte stream and the record-level fields used by the TLS session/protection path. It separates record framing from handshake-message semantics and cryptographic protection.

## 2. Data Model

A record has a content type, protocol-version/legacy-version fields as applicable, a length, and a fragment. The fragment may contain handshake messages, alerts, application data, or protected TLS 1.3 content. Record framing is distinct from the handshake-message header inside a handshake record.

```text
TLS record
  ├─ record header (type / version / length)
  └─ fragment
       ├─ handshake bytes -> handshake message parser
       ├─ alert bytes
       └─ protected application content
```

TLS and DTLS both use record concepts but have different wire headers and sequencing/transport constraints. QUIC does not wrap handshake data in ordinary TLS records; it carries TLS handshake bytes in CRYPTO frames.

## 3. Behavior Model

Incoming transport bytes are first separated into complete records according to the record length and the selected TLS version/path. The session/protection layer then authenticates/decrypts protected records as required and passes content to the appropriate parser. Outgoing content follows the reverse order: protocol content is serialized, protected with the active directional state, then framed as records and written to the stream.

The record parser must not assume that one TCP read equals one record; input can contain a partial record or several records.

## 4. Relationships

- Parent module: [TLS implementation](../README.md).
- [Handshake messages](../handshake/README.md) — handshake structures carried in record content.
- [Extensions](../extension/README.md) — extension data carried by handshake messages.
- [TLS protection](../../protection/README.md) — record authentication/encryption and key state.
- [TLS session support](../../session/README.md) — protocol state and record/session coordination.
- [DTLS record publisher](../../dtls_record_publisher.md) — datagram-specific record publication.
- [QUIC integration](../../quic/README.md) — CRYPTO frames replace ordinary TLS record framing in QUIC.

## 5. References

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
