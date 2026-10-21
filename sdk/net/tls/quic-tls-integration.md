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

### QUIC packet layer

`quic/packet/` models packet types and construction/processing, including:

- Initial
- Handshake
- 0-RTT
- 1-RTT
- Retry
- Version Negotiation
- packet builders / collections

Packet processing is above individual frame objects and below the session/transport layer.

### QUIC frame layer

`quic/frame/` models individual transport/control frames, including:

- ACK
- CRYPTO
- STREAM
- CONNECTION_CLOSE
- HANDSHAKE_DONE
- NEW_CONNECTION_ID
- NEW_TOKEN
- PING
- PADDING
- RESET_STREAM
- STOP_SENDING
- HTTP/3 stream-related frames

Frames are deliberately separate from packet assembly so that frame semantics and packet layout can evolve independently.

### TLS-derived secrets

The important boundary is:

```text
TLS handshake
     │
     ▼
TLS key schedule / traffic secrets
     │
     ▼
QUIC packet protection
     │
     ├── packet encryption
     └── header protection
```

QUIC therefore reuses TLS-derived cryptographic state without wrapping QUIC packets inside TLS records.

### Session and stream support

The QUIC session/stream helpers connect packet processing to transport state. HTTP/3 sits above this layer:

```text
HTTP/3
  │
  ▼
QUIC streams / frames
  │
  ▼
QUIC packets
  │
  ▼
UDP socket
```

## 3. Behavior Model

TLS 1.3 handshake messages are fed into QUIC's CRYPTO transport; QUIC frames and packets carry them over QUIC streams/connection state. TLS supplies handshake semantics and traffic-secret derivation, while QUIC applies its own packet encryption and header protection. The shared cryptographic inputs do not make TLS records and QUIC packets the same wire object.

Packet types/protection levels change as the handshake progresses (Initial, Handshake, 0-RTT and 1-RTT). 0-RTT has replay-related constraints and should not be described as equivalent to ordinary post-handshake application data.

## 4. Relationships



- `quic/rfc9000.md`
- `quic/rfc9001.md`
- `quic/rfc9369.md`
- [TLS/DTLS/QUIC overview](README.md)
- [QUIC implementation](quic/README.md)
- [QUIC packet publisher](quic_packet_publisher.md)
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
