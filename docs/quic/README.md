# QUIC

**Edition 1 · Revision 1076**

QUIC is a transport protocol built over UDP, but in hotplace it is also a
meeting point for TLS 1.3, packet protection, stream transport, and HTTP/3.
The document therefore treats QUIC as a protocol boundary rather than as a
collection of packet and frame classes.

## Context

The study path into QUIC is not isolated. HTTP/2 and HPACK lead toward the
header-compression problem, while HTTP/3 moves that problem onto QUIC streams.
TLS 1.3 is carried by QUIC CRYPTO frames and supplies the handshake and key
material used by QUIC packet protection.

```text
                 TLS 1.3
                    │
                    │ handshake / secrets
                    ▼
UDP ────────────── QUIC ────────────── HTTP/3
                    │                    │
                    │                    └── QPACK
                    │
             Packet / Frame
                    │
                    ▼
                  PCAP
```

The ownership boundary is intentional: QUIC owns transport packets, frames,
connection state, streams, and packet protection; TLS owns the TLS handshake
and cryptographic protocol; HTTP/3 owns application protocol frames and
QPACK. Traffic captures and test vectors connect the layers without making
one layer responsible for another.

## History

The CHANGELOG provides the chronological index for the current reconstruction.
The QUIC study appears together with the TLS study, and later entries record
RFC 9000/RFC 9001 work, QUIC Version 2 (RFC 9369), and HTTP/3 traffic
verification.

The concrete study path visible in the project is:

```text
TLS 1.3 study
    │
    ├── RFC 9001 / QUIC TLS protection
    │
    ▼
QUIC packet / frame study
    │
    ├── RFC 9000
    ├── RFC 9369
    └── packet construction
    │
    ▼
HTTP/3 traffic / PCAP study
```

The project history also records earlier QUIC verification at Revision 646
(Client Initial / Server Initial), Revision 647 (Retry), Revision 714
(quic.xargs.org), and Revision 716 (RFC 9369). These entries are useful as
historical anchors; they are not treated as a complete narrative of every
development step.

## Conceptual

### Packet

A QUIC packet carries a packet header and protected payload. The packet type
determines the header form and the protection space used by the implementation.

The current model distinguishes:

- Initial
- 0-RTT
- Handshake
- Retry
- Version Negotiation
- 1-RTT

### Frame

Frames are the transport-level units carried inside QUIC packets. The current
implementation includes, among others, ACK, CRYPTO, STREAM, PING, PADDING,
RESET_STREAM, STOP_SENDING, NEW_CONNECTION_ID, NEW_TOKEN, and
CONNECTION_CLOSE.

A packet is therefore not the same conceptual unit as a frame:

```text
QUIC packet
    │
    ├── header
    │
    └── protected payload
           │
           ├── frame
           ├── frame
           └── ...
```

### TLS binding

QUIC does not carry TLS records as its transport format. TLS handshake
messages are carried through QUIC CRYPTO frames, while the resulting traffic
secrets are used by QUIC packet protection.

```text
TLS handshake message
        │
        ▼
    CRYPTO frame
        │
        ▼
   QUIC packet
```

This distinction is central to understanding the TLS/QUIC implementation.

### Streams

QUIC provides multiplexed streams within one connection. Stream frames carry
application data, while stream state and connection state remain part of the
QUIC transport model.

For HTTP/3, the stream payload is subsequently interpreted as HTTP/3 frames,
and header blocks use QPACK.

```text
QUIC STREAM
    │
    ▼
HTTP/3 stream data
    │
    ├── HTTP/3 frame
    └── header block → QPACK
```

### Packet protection

Packet protection has two related but distinct operations: header protection
and payload protection. Packet-number reconstruction and protection-space
state participate in the decoding path.

The current implementation also represents QUIC v1/v2-specific key material
and labels through the TLS protection layer.

## Structural

The current source separates QUIC into packet, frame, session, and publishing
responsibilities.

```text
                    quic_session
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
     CID / settings   packet nums    quic_streams
                         │
                         ▼
                  quic_packet_publisher
                         │
               ┌─────────┴─────────┐
               ▼                   ▼
          quic_packets          TLS handshake
               │
               ▼
          quic_packet
               │
               ▼
          quic_frames
               │
        ┌──────┴─────────┐
        ▼                ▼
   transport frames   HTTP/3 stream
```

Important current source anchors are:

- `sdk/net/tls/quic/` — QUIC packet/frame model.
- `sdk/net/tls/quic/packet/` — packet parsing, writing, header protection,
  and packet-type-specific behavior.
- `sdk/net/tls/quic/frame/` — frame parsing and writing.
- `sdk/net/tls/quic_session.hpp` — connection-level state.
- `sdk/net/tls/quic_streams.hpp` — stream state.
- `sdk/net/tls/quic_packet_publisher.hpp` — packet construction and the
  connection point between TLS, QUIC frames, and HTTP/3 stream payloads.
- `sdk/net/basic/trial/tls_composer_quic_handshake.cpp` — composition of
  TLS 1.3 handshake messages into QUIC packets.

The class names above are source anchors, not the narrative itself. The
important structural idea is the separation between protocol state, packet
representation, frame representation, and packet publishing.

## Flow

### Receiving a packet

```text
UDP datagram
    │
    ▼
QUIC packet parser
    │
    ├── packet header
    ├── protection space
    ├── header unprotection
    ├── packet number
    └── payload decryption
             │
             ▼
          frames
             │
      ┌──────┴──────┐
      ▼             ▼
   CRYPTO        STREAM
      │             │
      ▼             ▼
     TLS          HTTP/3
```

### TLS handshake

```text
TLS ClientHello / ServerHello / ...
              │
              ▼
        CRYPTO frame
              │
              ▼
         QUIC packet
              │
              ▼
      packet publisher
```

The current trial handshake composer explicitly publishes the ClientHello
with HTTP/3 ALPN and QUIC transport parameters, then continues the handshake
through QUIC packet protection spaces.

### HTTP/3 traffic

```text
HTTP/3 application data
        │
        ▼
     QUIC STREAM
        │
        ▼
HTTP/3 frame parser
        │
        ├── control / settings
        ├── HEADERS
        └── DATA
                │
             QPACK
```

This is why HTTP/3 should refer to QUIC for transport behavior rather than
duplicating packet-level concepts.

## Study & Verification

The QUIC study is represented by both construction-oriented and
RFC-oriented material.

### RFC 9000

The transport protocol study covers packet and frame structures, variable
length integers, connection IDs, ACK ranges, STREAM/CRYPTO behavior, and
construction of QUIC packets.

Current study anchors include:

- `testcase_rfc9000.cpp`
- `testcase_construct_quic.cpp`
- `testcase_quic.cpp`

### RFC 9001

The TLS/QUIC security boundary is examined through QUIC-specific key
derivation, packet protection, header protection, and packet-number handling.

Current study anchor:

- `testcase_rfc9001.cpp`

### RFC 9369

QUIC Version 2 is studied separately because it changes version-specific
values and packet/key derivation details while retaining the broader QUIC
transport model.

Current study anchor:

- `testcase_rfc9369.cpp`

### 1-RTT construction

The transition from handshake protection to application traffic is examined
through 1-RTT packet construction.

Current study anchor:

- `testcase_construct_1rtt.cpp`

### Captured traffic

The HTTP/3 capture vector is particularly important because it connects the
abstract packet/frame model to real traffic. The current YAML vector records a
packet-by-packet sequence containing Initial, Handshake, and 1-RTT traffic,
ACK ranges, CRYPTO frames, STREAM frames, and HTTP/3 activity.

Current anchors:

- `testvector_pcap.cpp`
- `testvector_pcap_http3.yml`

The latest uploaded source archive was expected to contain additional
`.pcapng` material. In the archive inspected for Revision 1076, the actual
file list contains the YAML representation and the TLS `.pcap` capture, but no
file with a `.pcapng` extension was present. The YAML itself identifies the
source capture as `http3.pcapng` and contains the packet trace used by the
test. This discrepancy is recorded rather than guessed.

## Status

| Area | Current state |
| --- | --- |
| QUIC packet parsing/building | implemented |
| QUIC frame parsing/building | implemented |
| RFC 9000 study | implemented/studied |
| RFC 9001 study | implemented/studied |
| RFC 9369 study | implemented/studied |
| 1-RTT construction | implemented/studied |
| TLS 1.3 handshake composition | substantial |
| HTTP/3 stream integration | substantial |
| HTTP/3 captured-traffic verification | implemented/studied |
| QUIC `network_server` integration | not treated as complete |
| TLS composer / server integration | remaining work |

The status intentionally does not turn every open implementation question into
a TODO list. Current source, tests, and traffic vectors are the authority for
what has actually been implemented or verified.

## Related documents

```text
TLS ───────────────► QUIC ───────────────► HTTP/3
 │                    │                      │
 │                    └── Packet / Frame     └── QPACK
 │
 └── ASN.1 / X.509

HTTP/2 ─────────────► HPACK
```

Ownership remains separate:

- TLS owns the TLS protocol and cryptographic handshake.
- QUIC owns UDP-based transport, packet/frame state, streams, and QUIC packet
  protection.
- HTTP/3 owns the application protocol carried by QUIC streams.
- QPACK owns HTTP/3 header compression.
- HPACK owns HTTP/2 header compression.

The relationship map belongs in the project-level study index and should grow
only when a relationship becomes useful to explain a real study path.

## Publication

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1076            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```

## Related Documents

- [TLS](../tls/README.md)
- [HTTP/3](../http3/README.md)
- [Network Server](../network_server/README.md)
- [PCAPNG](../pcapng/README.md)
