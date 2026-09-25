# QUIC

**Edition 1 · Revision 1090**

QUIC is a transport protocol built over UDP, but in hotplace it is more useful to understand QUIC as the meeting point of four independently meaningful mechanisms:

```text
                    TLS 1.3
                       │
                 handshake / keys
                       │
                       ▼
UDP ──────────────── QUIC ─────────────── HTTP/3
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
          packets              streams
             │                   │
             ▼                   ▼
           frames             application
```

QUIC therefore cannot be reduced to either “UDP with reliability” or “TLS over UDP”. Its packet protection, connection state, stream transport, loss/acknowledgement behavior, and TLS handshake integration form one transport system while retaining distinct ownership boundaries.

## Context

The QUIC work in hotplace grew out of the TLS 1.3 study. RFC 9001 then provides the bridge: TLS supplies handshake semantics and key material, while QUIC transports TLS handshake bytes in CRYPTO frames and applies the resulting secrets to QUIC packet protection.

The surrounding study path is:

```text
HPACK / QPACK
      ↓
HTTP/2
      ↓
QUIC RFC 9000 / RFC 9001
      ↓
QUIC packet / frame / stream
      ↓
HTTP/3
      ↓
capture / replay verification
```

This also explains why QUIC touches several areas of the repository:

- `sdk/net/tls/quic/` — QUIC protocol model
- `sdk/net/tls/quic/frame/` — frame types
- `sdk/net/tls/quic/packet/` — packet types and protection
- `sdk/net/tls/quic/quic_encoded*` — QUIC variable-length encoding
- TLS protection — handshake and packet-protection key material
- HTTP/3 — stream/application interpretation
- PCAP/YAML test vectors — reproducible wire-level verification

### Reading Path

A first reading of QUIC should follow the boundary where each mechanism becomes
necessary:

```text
UDP datagrams
     ↓
QUIC packets
     ↓
frames and packet protection
     ↓
connection / loss / acknowledgement state
     ↓
streams and application data
     ↓
HTTP/3 interpretation
```

TLS enters this path at the handshake boundary rather than below every QUIC
operation:

```text
TLS handshake
     ↓
CRYPTO frames
     ↓
QUIC packets
     ↓
UDP

STREAM frames
     ↓
QUIC streams
     ↓
HTTP/3
```

The two paths meet inside a QUIC connection but retain different ownership.

## History

The CHANGELOG provides the chronological index.

Important anchors include:

- Revision 626: QPACK RFC 9204 tested.
- Revision 634–635: HPACK/QPACK tested.
- Revision 646: RFC 9001 Client Initial / Server Initial study.
- Revision 647: RFC 9001 Retry and TLS 1.3 study.
- Revision 714: `quic.xargs.org` study.
- Revision 716: RFC 9369 QUIC Version 2 study.
- Revision 823: RFC 9204 tested.
- Revision 824: QPACK fix.
- Later TLS/PQC work expanded the TLS foundation used by QUIC.

The historical relationship is therefore more informative than treating QUIC as an isolated feature:

```text
HTTP/2 / HPACK
       ↓
TLS 1.3
       ↓
RFC 9001
       ↓
QUIC packet + frame implementation
       ↓
RFC 9369 / QUIC v2
       ↓
HTTP/3 / capture replay
```

## Conceptual

### QUIC has multiple packet protection spaces

The packet type determines which cryptographic context is used.

```text
Initial
  └── Initial secrets

Handshake
  └── Handshake traffic secrets

0-RTT
  └── 0-RTT traffic secret

1-RTT
  └── application traffic secrets
```

Retry and Version Negotiation are special: they are not protected in the same way as ordinary encrypted packets.

The implementation consequently needs both packet-type dispatch and protection-space state.

### Packet and frame are different units

A QUIC packet is the transport/protection container:

```text
QUIC packet
 ├── header
 └── protected payload
       ├── frame
       ├── frame
       └── frame
```

A frame is the protocol operation carried inside that packet.

Examples include:

```text
ACK
CRYPTO
STREAM
PING
PADDING
RESET_STREAM
STOP_SENDING
NEW_CONNECTION_ID
NEW_TOKEN
CONNECTION_CLOSE
```

This distinction becomes important when reading the source: packet parsing establishes the protection boundary, while frame parsing establishes transport semantics.

### TLS is embedded through CRYPTO frames

QUIC does not carry TLS records.

```text
TLS handshake message
        ↓
TLS handshake bytes
        ↓
CRYPTO frame
        ↓
QUIC packet
```

The reverse path is:

```text
QUIC packet
   ↓
decrypt
   ↓
CRYPTO frame
   ↓
TLS handshake bytes
   ↓
TLS handshake parser
```

This is one of the central architectural boundaries in the implementation.

### Streams provide ordered application transport

A QUIC connection contains multiple streams.

```text
QUIC connection
 ├── stream 0
 ├── stream 1
 ├── stream 2
 └── ...
```

A STREAM frame carries a portion of one stream:

```text
STREAM frame
 ├── stream id
 ├── offset
 ├── optional FIN
 └── stream data
```

HTTP/3 then interprets the ordered stream data as HTTP/3 frames and QPACK-encoded header blocks.

### Variable-length encoding is part of the protocol model

QUIC uses a compact variable-length integer encoding for many fields. The implementation isolates this representation in `quic_encoded` and related helpers.

```text
value
  ↓
QUIC variable-length integer
  ├── 1 byte
  ├── 2 bytes
  ├── 4 bytes
  └── 8 bytes
```

Some protocol fields are additionally length-prefixed byte sequences:

```text
length(varint)
     ↓
data
```

This is where the generic `payload_encoded` model meets QUIC-specific wire representation.

### Packet protection has two layers

QUIC packet protection consists conceptually of:

```text
packet payload
     ↓
AEAD encryption
     ↓
ciphertext

packet header
     ↓
header protection
     ↓
protected header fields
```

Header protection is not the same operation as payload AEAD. Packet-number encoding/reconstruction participates in the boundary between them.

## Cross-Topic Boundary

QUIC is the transport/protocol boundary between UDP delivery and HTTP/3 stream semantics. Its relationship with TLS is deliberately asymmetric: TLS supplies handshake semantics and derived key material, while QUIC owns packets, frames, packet numbers, streams, and QUIC packet protection.

```text
TLS handshake message
        ↓
   CRYPTO frame
        ↓
   QUIC packet
        ↓
       UDP

HTTP/3
   ↓
QUIC stream
   ↓
QUIC packet/frame
```

The CRYPTO frame transports TLS handshake bytes; it does not reinterpret TLS messages. Likewise, HTTP/3 interprets QUIC stream data but does not own QUIC packet protection.

## Structural

### Overall source model

```text
                         quic_session
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
        connection CID   packet numbers    quic_streams
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                    packet construction/
                       publishing
                              │
                              ▼
                         quic_packet
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
                 header              frames
                    │                   │
                    │            ┌──────┴──────┐
                    │            ▼             ▼
                    │         CRYPTO        STREAM
                    │            │             │
                    ▼            ▼             ▼
             packet protection  TLS          HTTP/3
```

The implementation separates **connection state**, **packet representation**, **frame representation**, and **publishing/construction**.

### Packet family

The packet directory contains concrete packet forms:

```text
quic_packet
 ├── Initial
 ├── Handshake
 ├── 0-RTT
 ├── 1-RTT
 ├── Retry
 └── Version Negotiation
```

This is not merely an inheritance hierarchy. Each packet type has different header fields, packet-number behavior, and protection requirements.

### Packet parsing boundary

The receiving path is conceptually:

```text
UDP datagram
   ↓
packet type / header form
   ↓
header fields
   ↓
protection context
   ↓
header unprotection
   ↓
packet number reconstruction
   ↓
AEAD payload decryption
   ↓
frame parsing
```

The order matters. Frames cannot be interpreted until the protected payload has been recovered.

### Frame model

`quic_frame` is the common frame abstraction. Concrete implementations represent frame-specific fields and semantics.

```text
quic_frame
   ├── ACK
   ├── CRYPTO
   ├── STREAM
   ├── PING
   ├── PADDING
   ├── RESET_STREAM
   ├── STOP_SENDING
   ├── NEW_CONNECTION_ID
   ├── NEW_TOKEN
   ├── CONNECTION_CLOSE
   └── other registered frame types
```

`quic_frames` acts as the collection/dispatch boundary for a packet's frame sequence.

### CRYPTO frame is the TLS bridge

The CRYPTO frame is structurally simple but architecturally important:

```text
CRYPTO
 ├── offset
 ├── length
 └── TLS handshake bytes
```

The frame does not interpret TLS messages. It transports the bytes into the TLS layer.

This keeps the ownership boundary clean:

```text
QUIC → CRYPTO framing
TLS  → handshake interpretation
```

### STREAM frame is the application bridge

Similarly:

```text
STREAM
 ├── stream id
 ├── offset
 ├── FIN
 └── application bytes
```

The QUIC layer manages stream delivery semantics. HTTP/3 interprets the resulting stream bytes.

```text
QUIC STREAM
      ↓
HTTP/3
      ↓
HTTP/3 frame
      ↓
QPACK / application semantics
```

### `quic_encoded`

`quic_encoded` is the QUIC-specific representation used where the wire format is a variable-length integer or a length-prefixed data item.

Conceptually:

```text
quic_encoded
 ├── integer value
 │      └── encoded width
 │
 └── data value
        ├── data length
        ├── encoded length
        └── data bytes
```

Its relationship with the generic payload layer is important:

```text
payload_member
      ↓
payload_encoded
      ↓
quic_encoded
      ↓
QUIC wire encoding
```

Thus QUIC-specific compact encoding remains outside the generic payload implementation.

### Packet publisher

`quic_packet_publisher` is a construction/orchestration boundary.

It connects:

```text
TLS state
   +
QUIC packet
   +
QUIC frames
   +
HTTP/3 stream payload
```

This is particularly visible in the trial QUIC handshake path, where TLS handshake messages are converted into CRYPTO frames and then published into appropriate QUIC packets.

### Connection and stream state

`quic_session` represents connection-level state, while `quic_streams` manages stream-level organization.

The conceptual separation is:

```text
connection
 ├── connection identifiers
 ├── version
 ├── packet-number spaces
 ├── TLS / protection state
 └── streams
       ├── stream id
       ├── offset
       ├── direction
       └── application data
```

The transport can therefore multiplex independent ordered streams without turning each stream into a separate connection.

## Flow

### Initial packet

The RFC 9001 test path makes the complete construction chain visible:

```text
DCID / SCID / version
        ↓
Initial header
        ↓
CRYPTO frame
        ↓
TLS ClientHello
        ↓
PADDING
        ↓
packet payload
        ↓
Initial AEAD
        ↓
header protection
        ↓
wire packet
```

The Initial packet is special because its protection keys are derived from the Destination Connection ID and the QUIC version, before the normal TLS handshake secrets are available.

### Handshake packet

After the TLS handshake progresses:

```text
TLS handshake state
       ↓
Handshake traffic secret
       ↓
CRYPTO frame(s)
       ↓
Handshake packet
       ↓
AEAD + header protection
```

ACK frames may coexist with CRYPTO frames in the same packet.

### 1-RTT packet

After handshake keys become available:

```text
application / HTTP3 data
       ↓
STREAM frame(s)
       ↓
1-RTT packet
       ↓
payload AEAD
       ↓
header protection
       ↓
UDP datagram
```

### Receiving path

```text
UDP datagram
     ↓
packet classification
     ↓
header protection removal
     ↓
packet number reconstruction
     ↓
AEAD decryption
     ↓
frame sequence
     ├── ACK       → acknowledgement state
     ├── CRYPTO    → TLS handshake
     ├── STREAM    → stream state / HTTP3
     ├── PING      → connection behavior
     └── other     → frame-specific processing
```

### HTTP/3 path

```text
HTTP request
    ↓
HTTP/3 frame
    ↓
QUIC STREAM
    ↓
QUIC packet
    ↓
UDP
```

Receiving reverses the path:

```text
UDP
 ↓
QUIC packet
 ↓
STREAM frame
 ↓
ordered stream data
 ↓
HTTP/3 frame
 ↓
HEADERS / DATA
 ↓
QPACK / application
```

### QUIC version 2

QUIC v2 keeps the packet/frame architecture but changes version-specific wire/protection parameters. The implementation therefore keeps version-dependent constants and labels separate from the common packet/frame machinery.

The RFC 9369 test area is useful here because it verifies that the common QUIC model can be exercised with version-specific protection details.

## Study & Verification

### RFC 9000

`testcase_rfc9000.cpp` provides protocol-level verification for the QUIC transport behavior.

### RFC 9001

`testcase_rfc9001.cpp` reconstructs the RFC 9001 packet examples, including:

- Initial secrets
- client Initial
- server Initial
- packet protection
- packet header protection
- CRYPTO frame contents
- TLS handshake bytes

The Initial test explicitly checks expected unprotected/protected headers and final encrypted packet bytes.

This is valuable because it verifies the complete chain rather than testing only individual crypto primitives.

### RFC 9369

`testcase_rfc9369.cpp` verifies QUIC Version 2 behavior and its version-specific protection details.

### Construction tests

`testcase_construct_quic.cpp` and `testcase_construct_1rtt.cpp` exercise construction of packet/frame objects directly.

These complement the RFC vectors:

```text
construction test
      +
RFC known-answer test
      +
real traffic replay
```

### HTTP/3 capture replay

The HTTP/3 test area contains:

```text
http3.pcapng
sslkeylog
testvector_pcap_http3.yml
```

This provides a bridge between real traffic and deterministic replay.

The verification chain is:

```text
real HTTP/3 traffic
      ↓
PCAPNG
      ↓
SSL key log
      ↓
YAML packet/frame vector
      ↓
QUIC/TLS replay
      ↓
HTTP/3 interpretation
```

## Cross-Topic Verification

QUIC verification combines protocol vectors with captured traffic because packet protection and TLS handshake processing are coupled across layers. The repository keeps the responsibilities distinct even when one test exercises both.

```text
RFC 9000 / 9001 / 9369
          │
          ├── known packet / protection vectors
          │
real HTTP/3 traffic
          │
          ▼
        PCAPNG
          │
      SSLKEYLOG
          │
          ▼
   YAML capture vector
          │
      ┌───┴────┐
      ▼        ▼
    QUIC      TLS
      │        │
      └───┬────┘
          ▼
      HTTP/3 interpretation
```

This makes the verification boundary explicit: QUIC owns packet/frame/stream interpretation, TLS owns the handshake and secrets used by QUIC, and HTTP/3 interprets stream data above QUIC.

## Status

| Area | Revision 1090 state |
|---|---|
| QUIC packet model | implemented |
| QUIC frame model | broad implementation |
| Initial / Handshake / 0-RTT / 1-RTT | implemented |
| Retry / Version Negotiation | implemented |
| QUIC variable-length encoding | implemented |
| packet number / header protection | implemented |
| AEAD packet protection | implemented |
| TLS 1.3 handshake integration | implemented/tested |
| RFC 9000 vectors | present |
| RFC 9001 vectors | present |
| RFC 9369 / QUIC v2 | tested |
| HTTP/3 stream transport path | exercised/tested on the QUIC side |
| PCAP/YAML replay | implemented |
| broader loss/congestion/transport scheduling | separate / evolving area |

The current checkpoint therefore represents a substantial QUIC protocol study and implementation. The remaining breadth should be treated as transport-system work rather than as a reason to collapse TLS, packet, frame, and stream responsibilities into one layer.

## Related topics

```text
                     TLS 1.3
                        │
                 handshake / keys
                        │
                        ▼
UDP ──────────────── QUIC ─────────────── HTTP/3
                        │                    │
                  packet / frame           QPACK
                        │
                     stream
                        │
                      payload
```

The relationship to the previous payload and TLS studies is especially direct:

```text
payload
   ↓
TLS handshake / extensions
   ↓
QUIC CRYPTO frame
   ↓
QUIC packet
   ↓
UDP
   ↓
HTTP/3 STREAM
   ↓
HTTP/3 frame
```

This gives the current documentation set a useful vertical path from binary field construction to security protocol semantics to transport packetization to application protocol behavior.

---

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1090            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
