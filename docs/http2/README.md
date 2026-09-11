# HTTP/2

**Edition 1 · Revision 1072**

[← Document Guide](../guide/document-guide.md) · [Project document map](../README.md) · [HPACK](../hpack/README.md)

## Context

HTTP/2 is the protocol context in which HPACK appears.

The useful entry point is not HPACK by itself, but the path from an
HTTP/2 frame to the header block carried by that frame, and then to
the HPACK representation of that header block.

```text
HTTP/2 stream
     │
     ├── DATA
     ├── HEADERS
     ├── CONTINUATION
     └── other frames
             │
             │ HEADERS / CONTINUATION
             ▼
        Header Block
             │
             ▼
           HPACK
```

This document makes the **HTTP/2 frame and protocol context** the
protagonist. HPACK details remain in the
[HPACK document](../hpack/README.md).

HTTP/2 is therefore both a topic and a boundary: it explains where
the header block lives, while HPACK explains how that block is
represented.

## History

The project reached HTTP/2/HPACK through protocol study rather than
through a single isolated implementation task.

The study path later continued from HPACK/QPACK into QUIC, then into
TLS handshake and extension details, and eventually back to ASN.1.
That path is useful context for understanding why the project contains
protocol implementations together with RFC-oriented study cases.

The exact chronological details should be refined from project history
records when those records are available. This document does not
invent chronology that is not recorded.

## Conceptual

### Frame

An HTTP/2 connection carries protocol information as frames. A frame
provides the transport-level unit used by HTTP/2 streams to carry
different kinds of protocol data.

### HEADERS and Header Block

A HEADERS frame carries header-block information associated with an
HTTP/2 stream. A header block may also continue across CONTINUATION
frames.

Conceptually:

```text
HTTP/2
  │
  └── Stream
       │
       ├── HEADERS
       │     └── Header Block Fragment
       │
       └── CONTINUATION
             └── Header Block Fragment
                         │
                         ▼
                    Header Block
                         │
                         ▼
                       HPACK
```

The important boundary is that **HTTP/2 defines the frame and stream
context**, while **HPACK defines the representation of the header
fields inside the header block**.

### Relationship to HPACK

HPACK is not an alternative HTTP/2 frame type. It is the header
compression/representation mechanism used for HTTP/2 header blocks.

See [HPACK](../hpack/README.md) for:

- static and dynamic tables
- indexed and literal representations
- string encoding and Huffman coding
- dynamic table state
- encoder/decoder behavior

## Structural

The current source separates HTTP/2-related code from the HPACK
implementation.

```text
sdk/net/http/
├── hpack/
│   └── HPACK implementation
└── http2/
    └── HTTP/2 implementation
```

The current source anchors for HTTP/2 study are:

- `sdk/net/http/http2/`
- `test/testcase/net/http/`

HPACK-related study and verification is also connected through:

- `test/testcase/net/hpack/`
- `sdk/base/encoding/`
- `test/testcase/encode/`

The source names are navigation anchors rather than the subject of
this document. The stable subject is the relationship between
HTTP/2 framing, header blocks, and HPACK.

## Flow

### Receiving headers

```text
HTTP/2 bytes
    │
    ▼
┌──────────────┐
│ Frame parse  │
└──────┬───────┘
       │
       ▼
┌────────────────────┐
│ HEADERS /          │
│ CONTINUATION       │
└─────────┬──────────┘
          │
          ▼
   Header Block
          │
          ▼
      HPACK decode
          │
          ▼
     Header fields
```

### Sending headers

```text
Header fields
      │
      ▼
 HPACK encode
      │
      ▼
 Header Block
      │
      ▼
┌───────────────────┐
│ HEADERS /         │
│ CONTINUATION      │
└─────────┬─────────┘
          │
          ▼
      HTTP/2 bytes
```

The diagrams intentionally describe protocol flow rather than a
specific function-call sequence. Function names may change while
this relationship remains stable.

## Study & Verification

The HTTP/2/HPACK study is supported by concrete development traces.

### HPACK representation

The project studies the mechanisms needed to turn HTTP header fields
into a compact header block representation.

Current study anchors include the HPACK test cases and RFC-oriented
test vectors under:

- `test/testcase/net/hpack/`
- `test/testcase/encode/`

### Huffman coding

Huffman coding was studied as part of the string representation used
by HPACK.

Current source/test anchors:

- `sdk/base/encoding/`
- `test/testcase/encode/`

The encoding layer is therefore not merely a utility dependency in
the study narrative; it is one of the concrete places where the
HPACK representation can be examined and verified.

### RFC and test-vector work

The project contains RFC-oriented and test-vector-oriented study
around HPACK. These are useful because they connect the conceptual
model to concrete byte sequences.

The same approach is used elsewhere in the project: protocol
understanding is developed alongside executable examples, vectors,
and traffic analysis.

## Status

| Area | Current state |
|---|---|
| HTTP/2 topic study | documented at a bounded conceptual level |
| HTTP/2 frame context | included |
| HPACK relationship | defined and linked |
| Detailed HPACK mechanics | owned by [HPACK](../hpack/README.md) |
| HTTP/2 implementation history | requires further reconstruction |
| HTTP/2 ↔ network server integration | separate topic |

This document is intentionally a first bounded draft. More detailed
HTTP/2 material should be added only when it clarifies a question
owned by this topic.

## Publication

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1072            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```

## Related Documents

- [HTTP Server](../http_server/README.md)
- [HPACK](../hpack/README.md)
- [Network Server](../network_server/README.md)
- [PCAPNG](../pcapng/README.md)
