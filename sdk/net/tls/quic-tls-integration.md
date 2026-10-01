# QUIC and TLS integration

## Role

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

## QUIC packet layer

`quic/packet/` models packet types and construction/processing, including:

- Initial
- Handshake
- 0-RTT
- 1-RTT
- Retry
- Version Negotiation
- packet builders / collections

Packet processing is above individual frame objects and below the session/transport layer.

## QUIC frame layer

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

## TLS-derived secrets

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

## Session and stream support

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

## References retained elsewhere

Detailed protocol notes remain in:

- `quic/rfc9000.md`
- `quic/rfc9001.md`
- `quic/rfc9369.md`

The existing RFC documents should be treated as the study/reference layer; this document records the implementation boundary in hotplace.

## Related areas

- `quic/frame/`
- `quic/packet/`
- `session/`
- `../http/http3/`
- `../basic/`
- `sdk/crypto/`
