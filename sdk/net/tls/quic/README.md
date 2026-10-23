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

# QUIC transport and TLS integration

## 1. Role

`sdk/net/tls/quic` implements QUIC packet/frame representations and the integration between QUIC transport state and TLS 1.3 handshake/key material. Frame encoding, packet construction, session/stream state, packet-number tracking, and TLS handshake processing are separate responsibilities.

## 2. Data Model

### Packet and frame representations

The QUIC layer separates the packet envelope from the frames carried in its payload:

- **Packet model:** Initial, Handshake, 0-RTT, 1-RTT, Retry, and Version Negotiation packet classes/builders. Packet type identifies header layout and the applicable packet-number space.
- **Frame model:** ACK, CRYPTO, STREAM, PADDING, PING, connection-close and stream-control frames, plus implemented HTTP/3 stream-related frame integration. Each frame owns type-specific fields and encoding.
- **Encoded values:** QUIC variable-length integers and length-prefixed byte sequences are represented by QUIC encoding helpers, rather than ordinary fixed-width TLS fields.
- **Connection state:** `quic_session` retains connection IDs and transport settings; `quic_streams` tracks stream-oriented state.
- **Protection inputs and outputs:** Initial protection uses version-specific salt and destination connection ID; Handshake/Application protection uses TLS 1.3 traffic secrets with QUIC-specific labels. QUIC packet headers, packet numbers, keys, IVs, and header-protection values remain distinct from TLS record state.

### Packet-number spaces

- **Initial:** Initial packets and their packet numbers.
- **Handshake:** Handshake packets and their packet numbers.
- **Application Data:** 0-RTT and 1-RTT use the application-data packet-number space, while their protection and acceptance rules differ.

These packet numbers are not TLS record sequence numbers or DTLS epoch/sequence values. QUIC's packet-number representation and reconstruction algorithm are described in Behavior Model.

### TLS boundary

TLS handshake messages, QUIC CRYPTO frames, QUIC packets, and UDP datagrams are separate representations. QUIC CRYPTO carries handshake bytes but is not a TLS record; QUIC owns packet and frame wire formats.

## 3. Behavior Model

### Directional key selection and packet protection

Initial protection is the exception to a simple “TLS secrets first” description: the Initial secret is derived from the version-specific salt and destination connection ID, so Initial packets can be protected before TLS handshake traffic secrets exist. TLS 1.3 handshake processing later derives Handshake and Application traffic secrets, from which QUIC-specific keys are expanded. The QUIC packet path selects keys by direction and packet-number space. Initial, Handshake, and Application Data protection do not use the TLS record key selector or TLS record counter. For each packet, QUIC packet processing applies header protection and packet AEAD using the packet header/sample, packet number, and the appropriate QUIC key/IV/HP secret. TLS's handshake Finished check remains a handshake-layer operation, not a QUIC packet authentication operation.


### TLS handshake bytes across QUIC

```text
OUTGOING
TLS handshake message bytes
  -> QUIC CRYPTO frame (offset + data)
  -> QUIC packet publisher
  -> Initial / Handshake / 1-RTT packet
  -> QUIC packet protection and UDP datagram

INCOMING
UDP datagram
  -> packet protection / frame parsing
  -> CRYPTO frame data and offset
  -> reassembled TLS handshake bytes
  -> TLS handshake/session state
  -> key schedule updates QUIC protection keys
```

The two directions meet at the TLS/QUIC boundary, but they are not one synchronous call chain. CRYPTO frame offsets identify positions in the TLS handshake byte stream and allow data to be reassembled; packet protection and UDP delivery remain QUIC transport responsibilities. TLS handshake processing advances the transcript and key schedule, while QUIC installs the resulting traffic secrets as QUIC-specific packet-protection keys. Initial packet protection is a separate case derived from the version salt and destination connection ID.

### Receive and send responsibilities

1. Parse the QUIC packet header and packet type to establish the packet format and protection context.
2. Reconstruct/use the relevant packet number and select the corresponding packet-number space and traffic key context.
3. Remove header protection and authenticate/decrypt the packet payload through the QUIC packet path.
4. Parse the decrypted payload as a sequence of QUIC frames. A CRYPTO frame contributes TLS handshake bytes; STREAM frames contribute stream payload; ACK and control frames affect transport state.
5. Feed CRYPTO bytes into TLS handshake processing without wrapping them in a TLS record. The TLS handshake/key schedule can update traffic secrets; QUIC then uses the derived values for packet protection.
6. On output, the session publisher converts pending TLS handshake messages into CRYPTO frames and stream/application content into STREAM frames, packs frames within the configured payload target, and passes packet bytes to its callback/output boundary.

The exact order of TLS handshake state transitions and QUIC packet-space availability is stage-dependent. Packet/frame serialization, TLS transcript/key-schedule processing, packet protection, and actual UDP delivery are separate steps.

## 5. Relationships

- [Packet implementation](packet/README.md) — packet variants, headers, number and protection boundaries.
- [Frame implementation](frame/README.md) — CRYPTO, STREAM, ACK and control frames.
- `quic_packet_publisher.hpp/.cpp`, `quic_session.cpp`, `quic_streams.cpp`.
- [QUIC packet publisher](../quic_packet_publisher.md) and [TLS session support](../session/README.md).
- [TLS protection](../protection/README.md) — TLS 1.3 secrets and cryptographic operations.
- `sdk/net/http/http3/` — HTTP/3 above QUIC streams.

## 6. References

- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9369 — QUIC Version 2](https://www.rfc-editor.org/rfc/rfc9369)

## 7. Developer Notes

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
