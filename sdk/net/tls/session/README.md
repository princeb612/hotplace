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

# TLS/DTLS/QUIC session support

## 1. Role

This directory groups session-level responsibilities: TLS/DTLS session state, DTLS record arrangement/publication, QUIC session/stream state and packet publication, and SSLKEYLOG import/export. Some implementation files are physically in the parent `sdk/net/tls/` directory. The documentation grouping should not be mistaken for a single source directory or one common wire format.

## 2. Data Model

| Component | State / input | Output / responsibility |
|---|---|---|
| `tls_session` | Protocol mode, handshake state, directional protection context | Coordinates TLS/DTLS state and exposes session helpers |
| `dtls_record_arrange` | Peer address, record epoch/sequence, buffered record bytes | Bounded peer-scoped ordering/retrieval of records |
| `dtls_record_publisher` | Handshake objects, session, fragment/segment limits | DTLS records suitable for datagram publication |
| `quic_session` / `quic_streams` | Connection IDs, transport parameters, packet-number ranges, stream state | QUIC connection/stream state |
| `quic_packet_publisher` | Session, TLS handshake messages, frame layout, payload-size limit | QUIC packets containing frames |
| SSLKEYLOG importer/exporter | Diagnostic key-log lines and traffic secrets | Secret import/export for diagnostics |

### Sequence numbers are transport-specific

TLS uses record-layer sequence state; DTLS carries an epoch and record sequence number and may need reordering/retransmission handling; QUIC tracks packet numbers independently in its packet-number spaces. These values serve related replay/protection purposes but are not interchangeable counters.

## 3. Behavior Model

### DTLS receive arrangement

```text
UDP datagram + peer address
  -> dtls_record_arrange::produce
  -> validate record header / version / length
  -> extract epoch + 48-bit sequence
  -> derive peer cookie
  -> insert into peer-scoped ordering pool
  -> discard stale records / bound buffered window
  -> consume next available record with epoch + sequence
  -> DTLS session/parser
```

The arranger can receive multiple DTLS records in one input buffer. It validates each declared length before inserting it into the pool, groups state by a cookie derived from the peer address, and protects the pool with a critical section. Records older than the last consumed epoch/sequence are discarded; the implementation bounds a peer's packet map to 100 entries. This is a bounded arrangement mechanism, not a promise to recover every loss or retransmission pattern.

### DTLS send publication

```text
handshake objects
  -> serialize handshake message bytes
  -> dtls_record_publisher
       session must be DTLS
       split oversized handshake bodies into fragments
       apply fragment / segment limits
       form DTLS record output
  -> output container or callback
  -> datagram send path
```

The default handshake fragment size is 1024 bytes; `set_fragment_size` clamps it to 128–1024 bytes. The optional multi-handshake setting controls whether a record may contain multiple handshake messages. Fragment size is a publication limit, not an exact guarantee of total wire datagram size.

### QUIC packet publication

```text
TLS handshake message / frame input
  -> quic_packet_publisher (associated TLS/QUIC session)
  -> packet/frame layout
  -> QUIC packet builder
  -> packet-number-space + protection context
  -> callback receives packet bytes
  -> UDP transport sends datagram
```

The publisher's payload-size setting is initialized from the QUIC session's `max_udp_payload_size` transport parameter. ClientHello/ServerHello use the composer path; CRYPTO and stream frames have dedicated handling. The publisher constructs packets but does not itself deliver them through a UDP socket. QUIC uses TLS 1.3 handshake/key-schedule material but packet numbers, frames, and packet protection remain QUIC responsibilities.

### TLS session state and protection

```text
record/handshake input
  -> tls_session updates protocol and handshake state
  -> transcript checkpoint / key schedule as required
  -> tls_protection directional state
  -> TLS record protection OR QUIC packet protection inputs
  -> composer/publisher emits transport-specific wire units
```

The diagram is conceptual: the exact call order depends on protocol version and handshake state. Ordinary TLS records, DTLS records, and QUIC packets are separate output units and should be reviewed through their specific publisher/arranger paths.

### Lifetime and sensitive material

Publishers and arrangers depend on the associated session's current protocol/protection state. Keep their lifetime within the session lifecycle. SSLKEYLOG data can expose traffic secrets and must be treated as sensitive diagnostic output.

## 4. Relationships

- `tls_session.hpp/.cpp`, `dtls_record_arrange.hpp/.cpp`, `dtls_record_publisher.hpp/.cpp`.
- `quic_packet_publisher.hpp/.cpp`, `quic_session.hpp/.cpp`, `quic_streams.hpp/.cpp`.
- `sslkeylog_exporter.hpp/.cpp`, `sslkeylog_importer.hpp/.cpp`.
- [TLS protection](../protection/README.md) — transcript hashing, key schedule and protection.
- [QUIC packet/frame](../quic/README.md) — packet/frame encoding and CRYPTO integration.
- [TLS advisor](../advisor/README.md) — protocol identifier and parameter hints.
- [DTLS record arrangement](../dtls_record_arrange.md), [DTLS record publisher](../dtls_record_publisher.md), [QUIC packet publisher](../quic_packet_publisher.md).
- `test/testcase/tls/` and `test/testcase/quic/sample.cpp` — source-level protocol/trace paths.

## 5. References

- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
