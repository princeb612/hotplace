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
# QUIC and TLS integration

## 1. Role


QUIC uses TLS 1.3 for the cryptographic handshake, but QUIC does not use the TLS record layer as its packet format. The hotplace implementation reflects that separation.

```text
                    TLS 1.3
                       │
             handshake messages
                       │
                       ▼
                QUIC CRYPTO data
                       │
                       ▼
              QUIC packet layer
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        QUIC packet          QUIC frame
```

The TLS implementation supplies handshake/key-schedule concepts, while QUIC owns packet and frame encoding and packet protection.

## 2. Data Model

### Three distinct representations

- **TLS handshake message:** typed message fields and extensions, serialized to handshake bytes. It is processed by TLS handshake/session logic and contributes to the TLS transcript.
- **QUIC CRYPTO frame:** a QUIC frame carrying a byte range of the TLS handshake stream. It has QUIC frame encoding and offset/length semantics; it is not a TLS record.
- **QUIC packet:** packet header, packet-number context, one or more encoded frames, and packet-protection output. Packet construction and protection belong to QUIC.

The handshake, CRYPTO-frame, and packet objects are distinct representations. Their conversion and publication order is described in Behavior Model.

The cryptographic bridge has a version-specific boundary. QUIC Initial packet keys are derived from the version-specific fixed Initial salt and destination connection ID before TLS handshake traffic secrets are available. Handshake and Application packet keys, by contrast, are derived from TLS 1.3 traffic secrets using QUIC-specific labels. Both sets are separate from TLS record key/IV application paths; QUIC packet protection does not reuse TLS record counters or TLS record framing.

### State boundaries

- TLS session/protection state tracks handshake stage, transcript, negotiated cipher suite, and TLS-derived secrets.
- QUIC session state tracks connection IDs, transport parameters, packet-number spaces, and stream/transport state.
- QUIC packet/frame objects own wire fields and encoding.
- The packet publisher bridges pending TLS handshake and stream/frame content into packet/frame layout.

## 3. Behavior Model

### Quick map: bytes and keys cross different boundaries

```text
TLS handshake object
        |
        v
serialized handshake bytes
        |
        v
QUIC CRYPTO frame (offset + bytes)
        |
        v
QUIC frame collection / packet builder
        |
        +-----------------------------+
        |                             |
        v                             v
Initial packet keys             Handshake / Application
version salt + DCID             TLS traffic secret + QUIC labels
        |                             |
        +--------------+--------------+
                       |
              QUIC packet protection
          header protection + packet AEAD
                       |
                  UDP datagram

Not on this path: TLS record header or TLS record sequence number
```

The Initial-key branch can run before TLS handshake traffic secrets exist. Later packet-protection levels consume TLS-derived secrets, but all packet numbers, packet headers, and packet protection remain QUIC-owned.



### Handshake and packet integration

1. TLS handshake processing constructs or parses a typed handshake message. The serialized handshake bytes are the data passed across the TLS/QUIC boundary.
2. The publisher maps outgoing handshake bytes to CRYPTO frames; incoming CRYPTO frame data is supplied back to TLS handshake processing as handshake-stream bytes. No TLS record header is inserted between the handshake and CRYPTO frame.
3. TLS handshake/session logic updates transcript state and calculates stage-specific TLS 1.3 secrets when the handshake reaches the corresponding state.
4. QUIC Initial protection derives client/server Initial secrets from the version-specific Initial salt and destination connection ID. Once TLS handshake/application traffic secrets are derived, QUIC derives the corresponding QUIC-labelled key, IV, and header-protection values from those secrets. The packet path selects values by direction and packet-number space, then applies header protection and packet AEAD to QUIC packet structures.
5. Application protocol data takes the stream path instead: HTTP/3 and QPACK content is encoded as stream bytes and carried in STREAM frames, not CRYPTO frames.
6. Packet bytes are passed to the transport/output callback. The caller's UDP path, packet scheduling, ACK/loss recovery, and stream delivery remain outside the TLS message representation.

### Packet keys are selected independently of TLS record keys

The implementation derives QUIC-labelled key, IV, and header-protection values from TLS 1.3 secret stages. Packet protection selects them using direction and the QUIC protection space (Initial, Handshake, or Application Data). The packet path then handles QUIC packet-number reconstruction, header protection, packet AAD and AEAD. It does not wrap CRYPTO data in TLS records, and the TLS record sequence number must not be substituted for a QUIC packet number.

### What this boundary does not imply

Sharing the TLS handshake and key schedule does not make QUIC a TLS-record transport. TLS transcript processing, CRYPTO stream offsets, QUIC packet numbers, STREAM IDs, and TLS record sequence numbers are distinct state domains. The implementation's integration path should be reviewed across session, protection, publisher, packet, and frame code rather than inferred from one class alone.

## 4. Relationships
- `quic/rfc9000.md`
- `quic/rfc9001.md`
- `quic/rfc9369.md`
- [TLS/DTLS/QUIC overview](README.md)
- [QUIC implementation](quic/README.md)
- [QUIC packet publisher](session/quic_packet_publisher.md)
- [TLS key schedule](protection/tls_key_schedule.md)
- [TLS session support](session/README.md)

### Related areas

- `quic/frame/`
- `quic/packet/`
- `session/`
- `../http/http3/`
- `../basic/`
- `sdk/crypto/`
- `session/` — session and packet publisher lifecycle
- `protection/` — TLS-derived secrets and packet-protection primitives

## 5. References
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
