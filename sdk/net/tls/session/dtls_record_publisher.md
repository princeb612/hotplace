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
# DTLS record publisher

## 1. Role

This document records the session-level send-side adapter that takes the shared TLS handshake record representation and constructs DTLS-specific records, including handshake fragmentation and record segmentation.

## 2. Data Model

### Inputs and intermediate representation

The publisher accepts TLS record objects, especially handshake records, but its output is DTLS record bytes. These are distinct representations:

| Data | Important fields / purpose |
|---|---|
| Source handshake | Handshake type, encoded message body, original handshake sequence |
| Fragment descriptor | Handshake type and sequence plus fragment offset/length and first/last boundary information |
| Fragment object | dtls_handshake_fragmented serializes the DTLS-specific fragment header around a slice of the original handshake body |
| Record builder state | DTLS record header and content, grouped according to publication flags and segment boundary |
| Output | Binary record units delivered to a list/container or callback |

The publisher is attached to a tls_session and checks that the session type is DTLS before building DTLS output. Its default fragment size is 1024 bytes; set_fragment_size clamps to 128–1024 bytes. The default segment target is 1200 bytes. Fragment size and segment size apply at different stages and are not interchangeable.

The multi-handshake publication flag controls whether separate handshake messages may share a record. It does not remove the need to preserve each handshake message's sequence and fragment metadata. The source-to-output sequence is described in Behavior Model.

## 3. Behavior Model

### Fragment and record boundary map

```text
serialized handshake message
             |
       split header/body
             |
        handshake body
             |
     body length > fragment limit?
          /             \
        no               yes
        |                 |
  one body range     multiple body ranges
        |                 |
        +--------+--------+
                 |
     fragment offset + length
     + original handshake sequence
                 |
       DTLS fragment serialization
                 |
       record grouping/segmentation
                 |
         output record units
```

Two boundaries are involved: fragment size limits one handshake-body slice, while record grouping/segment policy determines which serialized fragments share an output record or segment.

### Publication modes: one handshake per record vs multiple handshakes per record

The flag is checked in the splitter callback, after each source handshake has been serialized and split into body ranges. It changes **record boundaries**, not handshake serialization, fragment size, or the handshake sequence assigned to each source message.

| Mode | Boundary rule | Practical result |
|---|---|---|
| `set_flags(0)` (default) | Start a new record at each new segment **and** at the start of each source handshake (`splitter_new_group`). | Each handshake starts in a fresh DTLS record. If a handshake body is fragmented, its fragments are emitted in separate records as their segments begin. Easier to control each handshake's record boundary/size. |
| `set_flags(dtls_record_publisher_multi_handshakes)` | Start a new record at a new segment; do not force a record boundary just because the next source handshake begins. | Multiple handshake messages, or fragments belonging to adjacent handshakes, can share one DTLS record when they fall within the same segment. A segment boundary still starts a new record. |

```text
Input tls_record_handshake
  [ServerHello] [Certificate] [ServerKeyExchange] [ServerHelloDone]
          |             |                |                |
          +-------------+----------------+----------------+
                                |
                 serialize each handshake separately
                 retain its own handshake sequence
                                |
                     split each encoded body
                                |
                 +--------------+--------------+
                 |                             |
             flags = 0                 multi_handshakes
                 |                             |
      new segment OR new handshake      new segment only
                 |                             |
        record boundary at each         share current record
        handshake start                 until segment boundary
                 |                             |
      smaller, isolated record set      records may contain
                                       adjacent handshake content
```

The splitter's segment counter is based on the cumulative handshake-body bytes processed, with `get_fragment_size()` used as its segment size. It is **not** a direct calculation of the final DTLS record length: record and fragment headers add overhead, so `set_fragment_size()` and `set_segment_size()` should not be read as exact wire-size guarantees.

### Example from `testcase_construct_dtls12_2.cpp`

The testcase constructs one source handshake record containing ServerHello, Certificate, ServerKeyExchange, and ServerHelloDone, then runs the same construction path with both flag settings. Its comments illustrate the intended difference:

- **Flag off:** the four handshake messages begin in separate records; a large Certificate or ServerKeyExchange may occupy multiple fragment records. The test comments enumerate record sequence progression through the ServerHelloDone record.
- **Flag on:** handshake content from neighboring messages can share a record/segment. The comments specifically show a record containing ServerHello plus Certificate, another containing Certificate plus ServerKeyExchange, and another containing ServerKeyExchange plus ServerHelloDone. Large messages may therefore appear as fragments across adjacent records while sharing a record with neighboring handshake content where the segment boundary permits it.

Two sequence spaces must not be conflated: the handshake sequence identifies each logical handshake message, while the DTLS record sequence identifies each emitted record. Grouping can reduce the number of emitted records without merging the logical handshake messages or replacing their handshake sequence numbers.

```text
flags off:
  record(seq 1): ServerHello
  record(seq 2..): Certificate fragments
  record(...): ServerKeyExchange fragments
  record(...): ServerHelloDone

multi_handshakes:
  record(seq 1): ServerHello + initial Certificate fragment(s)
  record(seq ...): remaining Certificate fragment(s) + ServerKeyExchange fragment(s)
  record(seq ...): remaining ServerKeyExchange fragment(s) + ServerHelloDone
```

This is a conceptual view of the testcase comments, not a fixed record-count promise: exact boundaries depend on encoded message sizes and the configured fragment/segment size.
### Publish flow

1. Reject a null source record and fail if no session is attached or the session is not DTLS.
2. Retain the source record while the publication path examines its record/handshake collection.
3. For a handshake record, serialize each handshake object to obtain the canonical encoded message, then separate its handshake header from the body that will be fragmented.
4. Pass the body and a descriptor containing handshake identity/sequence to the splitter. Each emitted range supplies the fragment offset, length, and boundary information needed to construct a DTLS handshake fragment.
5. Serialize each fragment into a DTLS record. The record builder and segment/grouping logic determine output boundaries, including whether multiple handshake messages may share a record.
6. Return generated binary records through the caller-selected container or callback. The caller remains responsible for actual datagram transmission.

### Boundaries and failure interpretation

Fragmentation addresses the handshake-body limit; record segmentation/grouping addresses output-unit boundaries. A successful publish means the implementation generated output bytes, not that a peer received them, that a complete handshake flight fits one datagram, or that loss/retransmission has been handled. Receive-side record validation and ordering are implemented by dtls_record_arrange, not by this publisher.

## 5. Relationships
- [TLS/DTLS/QUIC overview](../README.md)
- [DTLS record arrangement](dtls_record_arrange.md)
- [TLS session support](README.md)
- [Network session model](../../server/network_session.md)
### Session relationship

```text
tls_session
    |
    +-- dtls_record_publisher
    |      |
    |      +-- TLS handshake record
    |      +-- DTLS handshake fragmentation
    |      +-- record segmentation
    |
    +-- dtls_record_arrange
    |      +-- receive-side reordering
    |
    +-- protection / record layer
```

The publisher is the **send-side construction** counterpart to `dtls_record_arrange`, which performs receive-side ordering.

### Implementation and source examples

- `dtls_record_publisher.hpp` and `session/dtls_record_publisher.cpp` — public interface and the serialization/splitter callback path.
- `tls/handshake/dtls_handshake_fragmented.cpp` — writes the fragment header and selected handshake-body bytes.
- `test/testcase/tls/testcase_construct_dtls12_1.cpp` and `testcase_construct_dtls12_2.cpp` — construction examples; `test/testcase/tls/sample.cpp` contains additional usage examples.

## 6. References
- [RFC 6347 — Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347) — protocol context for DTLS handshake and record fragmentation.
