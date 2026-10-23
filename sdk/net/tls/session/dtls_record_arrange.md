## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# DTLS record arrangement

## 1. Role

This document records the session-level receive-side ordering adapter that turns possibly reordered UDP datagrams into the next expected DTLS record for the shared TLS/DTLS session path.

## 2. Data Model

### Peer and record state

dtls_record_arrange groups incoming DTLS 1.2 records by a cookie derived from the peer sockaddr. A peer entry tracks the current epoch and next expected 48-bit record sequence, with stored records held under an ordered epoch/sequence key. The per-peer map is bounded to 100 stored entries.

The key is formed from a 16-bit epoch and 48-bit record sequence; it represents **record ordering**, not the DTLS handshake message sequence. Handshake sequence numbers are carried inside handshake messages and serve a different purpose.

### Input and output representation

| Data | Meaning |
|---|---|
| Datagram input | Raw bytes plus peer address; may contain multiple consecutive DTLS records |
| DTLS record header | Version, declared record length, epoch, and 48-bit record sequence |
| Peer cookie | Address-derived lookup key for isolating each peer's ordering state |
| Ordered pool entry | One record's bytes indexed by combined epoch/sequence |
| Consume result | Next available record bytes, optionally with epoch and sequence returned separately |

The stored record representation is keyed by the pair `(epoch, record sequence)` within a peer-specific pool. Parsing, validation, insertion, and next-record selection are execution steps described in Behavior Model.

## 3. Behavior Model

### Expected-record decision map

```text
incoming datagram
       |
parse each complete DTLS record
       |
validate version + declared length
       |
key = peer cookie + (epoch, record sequence)
       |
insert into bounded ordered pool
       |
request next expected record
       |
       +-------------------------------+
       |               |               |
  expected exists   expected absent   older than expected
       |               |               |
 return record      wait / no next    discard as stale
       |
 advance expected epoch/sequence
       |
ChangeCipherSpec? -- yes --> next epoch, sequence reset
       |
      no
       |
advance record sequence in current epoch
```

The pool orders records that have arrived; it does not synthesize a missing record or replace handshake-flight retransmission logic.

For example, records may arrive out of order:

```text
arrival order:
  epoch 0, seq 0
  epoch 0, seq 2
  epoch 0, seq 1

consumption order:
  epoch 0, seq 0
  epoch 0, seq 1
  epoch 0, seq 2
```

The later record (sequence 2) remains buffered until the expected sequence 1 is available. This illustrates ordering within one epoch; it does not imply that a missing record can be reconstructed or that the consumer proceeds past a gap.

### Receive arrangement flow

1. Reject invalid address/input pointers or a buffer too short to contain a DTLS header.
2. Derive a cookie from the peer address. This partitions the pool so records from different peer addresses do not share sequence state.
3. Walk the datagram from the current offset. For each record, ensure a complete header is present, confirm that the version is recognized as DTLS, and ensure the declared record length stays within the input buffer.
4. Read the epoch and 48-bit record sequence and build the ordered key. Under the critical section, insert the record into that peer's pool subject to stale-record and capacity rules.
5. On consume, inspect the next expected epoch/sequence. If that record is not available, the caller cannot consume a later record as though the gap did not exist. When the expected record is returned, advance the expected position.
6. A ChangeCipherSpec transition updates the expected epoch and resets its sequence position; ordinary records advance the sequence within the current epoch.

Records older than the current expected position are treated as stale/retransmitted input. The pool provides bounded ordering of records that arrived; it does not reconstruct missing records, guarantee complete retransmission behavior, or replace DTLS handshake-flight management.

## 4. Relationships
- `dtls_record_arrange.hpp`
- `session/dtls_record_arrange.cpp`
- `test/testcase/tls/testcase_dtls_record_arrange.cpp`
- `test/testcase/tls/testcase_construct_dtls12_1.cpp`
- `test/testcase/tls/testcase_construct_dtls12_2.cpp`
- [TLS/DTLS/QUIC overview](../README.md)
- [TLS session support](README.md)
- [DTLS record publisher](dtls_record_publisher.md)
- [Network session model](../../server/network_session.md)
### Session relationship

```text
tls_session
    |
    +-- dtls_record_arrange
    |      +-- peer-address pool
    |      +-- epoch / sequence tracking
    |      +-- reordering
    |
    +-- dtls_record_publisher
    |
    +-- QUIC session / publisher
```

The class is concerned with **receive-side ordering**. It does not construct DTLS handshake fragments; that responsibility belongs to `dtls_record_publisher`.

## 5. References
- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147)
