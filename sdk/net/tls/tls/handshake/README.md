## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1107                  │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS handshake messages

## 1. Role

The handshake layer represents typed TLS/DTLS negotiation messages and their structured fields. It does not own the complete connection state machine: the session/composer path decides which message to construct or expect, while the protection path manages transcript checkpoints, key derivation, and protected traffic.

The same TLS handshake-message model is reused for QUIC. The source bytes arrive through QUIC CRYPTO data rather than ordinary TLS records; QUIC stream offsets, packet framing, and packet protection remain separate concerns.

## 2. Data Model

### Message object

`tls_handshake` holds the message type, session association, body size, parsed header range, total size, extension collection, and flags. Its interface separates `read()`/`write()` from the overridable header/body methods. Type-specific subclasses supply message-specific field encoding and decoding.

For DTLS, the same object also has message-sequence and fragment metadata: sequence number, fragment offset, fragment length, and reassembled size. These fields describe the DTLS handshake-fragment representation; they do not turn a fragment into a different logical handshake type.

```text
tls_handshake
  ├─ message type / body length / session association
  ├─ type-specific fields
  ├─ extension collection (when defined)
  └─ DTLS-only fragment metadata
       ├─ handshake sequence
       ├─ fragment offset
       └─ fragment length / reassembled size
```

The object retains a `tls_session*` association, and the public API exposes reference-count operations. It owns the typed message state rather than acting only as a passive view into an input buffer.

### Important data boundaries

- **Typed fields:** values decoded by a concrete handshake subclass; consumed by negotiation/session logic or written back to bytes.
- **Serialized handshake bytes:** the handshake header and body emitted by the handshake writer; these bytes can feed TLS records, DTLS fragmentation/publication, or QUIC CRYPTO frames.
- **Transcript input:** protocol-selected handshake bytes processed by the protection/session path. Record headers and arbitrary transport bytes are not interchangeable with transcript input.
- **DTLS fragment metadata:** message sequence and byte-range coordinates used when a logical message is fragmented/reassembled.

## 3. Behavior Model

### Quick map: message object lifecycle

```text
RECEIVE                                      SEND
wire byte range                              typed fields + extensions
      |                                               |
      v                                               v
tls_handshake::read()                       tls_handshake::write()
      |                                               |
read header / body                           write body / header
      |                                               |
typed message fields                         serialized handshake bytes
      |                                               |
pre/post-processing hooks                    selected output boundary
      |                                      /          |          \
      v                                  TLS record  DTLS publish  QUIC CRYPTO
session / transcript / key state
      |
DTLS adds fragment/reassembly metadata
QUIC supplies handshake bytes from CRYPTO data
```

Parsing or serializing a message is not the same as completing a handshake transition. The surrounding session path decides when to validate the message, update transcript state, change directional status, and schedule follow-up work.


### Parse path

1. The caller provides a byte range, direction, session, and mutable position to `tls_handshake::read(session, dir, stream, size, pos)`.
2. The handshake type is used to construct the appropriate concrete message representation; the selected object reads its header and declared body.
3. Header and body parsing proceed through the base read path and overridable `do_read_header()` / `do_read_body()` methods. Message-specific readers decode their own fields and nested extensions where present.
4. Pre/post-processing hooks allow the message path to check message flow and perform state-related work, including transcript/key-calculation responsibilities where implemented.
5. The parsed object is returned to the caller. Parsing alone is not equivalent to completing the protocol transition: the caller/session still owns sequencing, negotiation decisions, and protection-state changes.

The mutable position is significant: a handshake parser operates on a byte range that may contain subsequent protocol data, rather than assuming that one input buffer equals exactly one message.

### Write path

1. The caller constructs a concrete handshake object and fills its typed fields and extension collection.
2. The base write path invokes message-specific body serialization and writes the handshake header using the resulting body size.
3. The resulting handshake bytes are handed to the selected transport path: ordinary TLS record construction, DTLS fragment/record publication, or QUIC CRYPTO-frame integration.
4. Protection and output framing occur at their respective layers; the handshake writer itself does not send bytes over a socket or assemble a QUIC packet.

### State and protocol boundaries

- TLS 1.2 and TLS 1.3 use different handshake sequences and protection transitions; a shared message type model does not imply one shared state machine.
- A record boundary need not equal a handshake-message boundary.
- DTLS adds message fragmentation and ordering/reassembly concerns.
- QUIC carries TLS handshake bytes in CRYPTO frames and uses QUIC packet-number spaces and packet protection.

### Real-code example: one handshake object, several output boundaries

The TLS server integration in `test/applet/tlsserver/run_server.cpp` selects a backend and starts a session; handshake objects are processed beneath its `consumer_routine`. To study an isolated handshake/record relationship, compare the captured-record assertions in `test/testcase/tls/testcase_tls12_aead.cpp` with this message lifecycle diagram.

```text
typed handshake message
  -> tls_handshake::write()
  -> TLS: TLS record publisher
     DTLS: DTLS record arrangement/publication
     QUIC: CRYPTO frame and QUIC packet path
```

The same handshake semantics do not imply the same transport encoding. The applet shows the live caller boundary; the focused testcase is for cryptographic record behavior, not a complete handshake transcript.

## 5. Relationships
- Parent module: [TLS implementation](../../README.md).
- [TLS records](../record/README.md) — record framing and content dispatch.
- [Extensions](../extension/README.md) — nested typed extension payloads.
- [TLS protection](../../protection/README.md) — transcript processing, Finished verification, and key derivation.
- [TLS protection/session flow](../../tls-protection-and-session.md) — source-level ordering of Finished verification, transcript update, key derivation, and deferred session-state work.
- [TLS session support](../../session/README.md) — session lifecycle and handshake status.
- [Trial TLS composer](../../../basic/trial-socket-composer.md) — source example for constructing and publishing handshake flights.
- [QUIC](../../quic/README.md) — TLS handshake bytes carried by CRYPTO frames.

## 6. References
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147)
