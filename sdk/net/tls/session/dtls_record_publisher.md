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
