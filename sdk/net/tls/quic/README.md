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

# QUIC transport and TLS integration

## 1. Role

`sdk/net/tls/quic` implements QUIC packet/frame representations and the integration between QUIC transport state and TLS 1.3 handshake/key material. Frame encoding, packet construction, session/stream state, packet-number tracking, and TLS handshake processing are separate responsibilities.

## 2. Data Model

### Packet-number spaces and protection

QUIC packet numbers are tracked by QUIC packet-number space, not by TLS record sequence numbers or DTLS record epoch/sequence numbers.

- **Initial space:** Initial packets and their packet numbers.
- **Handshake space:** Handshake packets and their packet numbers.
- **Application Data space:** 0-RTT and 1-RTT packet-number handling belongs to QUIC's application-data space, although the two packet types have different protection/acceptance rules.

TLS record sequence numbers are implicit record-layer state; DTLS uses epoch plus record sequence number; QUIC carries a truncated packet number in its packet header and reconstructs it within the applicable packet-number space. These numbering schemes are not interchangeable.

### Frame and packet

A frame is a unit inside a QUIC packet. A packet adds packet type, connection IDs, packet-number encoding, and protection context around one or more frames. The packet publisher combines handshake/frame material with packet layout; packet/session code handles packet numbers and packet protection.

### CRYPTO and TLS handshake

QUIC's CRYPTO frame carries a byte range of TLS handshake data at a CRYPTO offset. It does not carry a TLS record. The TLS handshake parser consumes the reassembled CRYPTO byte stream as handshake messages, and the TLS key schedule supplies secrets that QUIC uses for packet protection.

```text
TLS handshake message bytes
  -> QUIC CRYPTO frame (offset + data)
  -> QUIC packet publisher
  -> Initial / Handshake / 1-RTT packet
  -> QUIC packet protection and UDP datagram

incoming packet
  -> packet protection / frame parsing
  -> CRYPTO frame data and offset
  -> reassembled TLS handshake bytes
  -> TLS handshake/session state
  -> key schedule updates QUIC protection keys
```

## 3. Behavior Model

QUIC handshake processing coordinates two state machines: TLS determines handshake-message and key-schedule progress; QUIC determines packet-number space, packet protection, CRYPTO offsets, transport parameters, connection IDs, and stream state. A TLS status transition can make new keys available, but QUIC must install/use them in the correct packet-number space and packet type.

The `quic_packet_publisher` constructs packets from handshake/frame material and is distinct from the UDP send operation. Its payload-size setting is a packet-construction limit informed by QUIC transport parameters, not the DTLS record publisher's fragment-size setting.

## 4. Relationships

- [Packet implementation](packet/README.md) — packet variants, headers, number and protection boundaries.
- [Frame implementation](frame/README.md) — CRYPTO, STREAM, ACK and control frames.
- `quic_packet_publisher.hpp/.cpp`, `quic_session.cpp`, `quic_streams.cpp`.
- [QUIC packet publisher](../quic_packet_publisher.md) and [TLS session support](../session/README.md).
- [TLS protection](../protection/README.md) — TLS 1.3 secrets and cryptographic operations.
- `sdk/net/http/http3/` — HTTP/3 above QUIC streams.

## 5. References

- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9369 — QUIC Version 2](https://www.rfc-editor.org/rfc/rfc9369)

## 6. Developer Notes

These notes retain the RFC handshake examples and TLS/QUIC interaction diagrams used while developing this area. They complement the implementation model above rather than defining another source-tree module.

### RFC summaries

- [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) — [local summary](rfc9000.md)
- [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001) — [local summary](rfc9001.md)
- [RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369) — [local summary](rfc9369.md)

### RFC 9000

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                          Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
                                    <- 1-RTT[0]: STREAM[1, "..."]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[0]: STREAM[0, "..."], ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[0]

                     Figure 5: Example 1-RTT Handshake
```

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH]
   0-RTT[0]: STREAM[0, "..."] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                                     Handshake[0] CRYPTO[EE, FIN]
                             <- 1-RTT[0]: STREAM[1, "..."] ACK[0]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[1]: STREAM[0, "..."] ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[1]

                     Figure 6: Example 0-RTT Handshake
```

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

               Figure 7: Use of Connection IDs in a Handshake
```

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                       <- Retry: DCID=C1, SCID=S2
   Initial: DCID=S2, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

         Figure 8: Use of Connection IDs in a Handshake with Retry
```

### RFC 9001

```
   +------------+                               +------------+
   |            |<---- Handshake Messages ----->|            |
   |            |<- Validate 0-RTT Parameters ->|            |
   |            |<--------- 0-RTT Keys ---------|            |
   |            |<------- Handshake Keys -------|            |
   |            |<--------- 1-RTT Keys ---------|            |
   |            |<------- Handshake Done -------|            |
   +------------+                               +------------+
    |         ^
    | Protect | Protected
    v         | Packet
   +------------+
   |   QUIC     |
   |  Packet    |
   | Protection |
   +------------+

                    Figure 4: QUIC and TLS Interactions
```

```
   Client                                                    Server
   ======                                                    ======

   Get Handshake
                        Initial ------------->
   Install tx 0-RTT keys
                        0-RTT - - - - - - - ->

                                                 Handshake Received
                                                      Get Handshake
                        <------------- Initial
                                              Install rx 0-RTT keys
                                             Install Handshake keys
                                                      Get Handshake
                        <----------- Handshake
                                              Install tx 1-RTT keys
                        <- - - - - - - - 1-RTT

   Handshake Received (Initial)
   Install Handshake keys
   Handshake Received (Handshake)
   Get Handshake
                        Handshake ----------->
   Handshake Complete
   Install 1-RTT keys
                        1-RTT - - - - - - - ->

                                                 Handshake Received
                                                 Handshake Complete
                                                 Handshake Confirmed
                                              Install rx 1-RTT keys
                        <--------------- 1-RTT
                              (HANDSHAKE_DONE)
   Handshake Confirmed

             Figure 5: Interaction Summary between QUIC and TLS
```

### Implementation areas

- [frame](frame/README.md)
- [packet](packet/README.md)
- [TLS integration](../README.md)

### Related areas

- `sdk/net/http/http3/` — HTTP/3 above QUIC
- `sdk/net/tls/` — TLS 1.3 handshake and key schedule used by QUIC
- `sdk/crypto/` — packet-protection cryptography
