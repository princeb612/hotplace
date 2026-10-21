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

# TLS handshake messages

## 1. Role

The handshake layer represents TLS negotiation messages and their structured fields. It is distinct from the record layer that transports handshake bytes and from the session/composer logic that decides which message to send or expect next.

## 2. Data Model

Handshake messages have a message type, a length, and a type-specific body. The family includes ClientHello, ServerHello/HelloRetryRequest, EncryptedExtensions, Certificate, CertificateVerify, Finished, key-exchange messages in legacy versions, and other version-specific messages. Extensions are nested inside applicable handshake messages rather than being record types.

```text
TLS record fragment
  -> handshake message header
  -> handshake type + length
  -> type-specific message fields
       └─ extension list where defined
```

The transcript hash consumes protocol-defined handshake-message bytes, while the key schedule consumes transcript checkpoints and negotiated inputs. Neither the record header nor application-data payload is simply treated as another handshake message.

## 3. Behavior Model

The parser reconstructs complete handshake messages from record content. The session updates its handshake status and transcript-related state; the composer/session logic uses that state to decide the next handshake flight. TLS 1.2 and TLS 1.3 have different message sequences and protection transitions, so the message model alone does not define the full handshake state machine.

For QUIC, the same TLS 1.3 handshake-message model is fed by CRYPTO frame data rather than ordinary TLS records. QUIC's CRYPTO offset/reassembly and packet protection remain in the QUIC layer.

## 4. Relationships

- Parent module: [TLS implementation](../README.md).
- [TLS records](../record/README.md) — transport framing for TLS handshake bytes.
- [Extensions](../extension/README.md) — nested extension structures.
- [TLS protection](../../protection/README.md) — transcript hashing, Finished and key derivation.
- [TLS session support](../../session/README.md) — state transitions and session lifecycle.
- [Trial TLS composer](../../../basic/trial-socket-composer.md) — example implementation flow for constructing and publishing handshake flights.
- [QUIC](../../quic/README.md) — TLS handshake bytes carried in CRYPTO frames.

## 5. References

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
