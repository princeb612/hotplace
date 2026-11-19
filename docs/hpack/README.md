# HPACK

Edition 1 · Based on hotplace Revision 1132

> Source base : Revision 1132

> This document follows the [Document Guide](../guide/document-guide.md).

## Context

HPACK is used by HTTP/2 to represent Header Blocks.

```text
HTTP/2
  │
  └── Frame
       │
       └── HEADERS
            │
            └── Header Block
                 │
                 └── HPACK
```

The HTTP/2 frame model belongs to the HTTP/2 document. Here it is shown only
to establish HPACK's position.

HPACK is one branch of the HTTP header-field representation problem:

```text
HTTP/2 ──► Header Block ──► HPACK

HTTP/3 ──► Field Section ──► QPACK
              │
              ▼
             QUIC
```

HPACK and QPACK address related representation problems, but they belong to
different protocol contexts. HPACK is the HTTP/2 mechanism; QPACK is the
HTTP/3 mechanism designed for QUIC's multiplexed transport model. This
document focuses on HPACK; the HTTP/3 document keeps the QPACK relationship
at the protocol boundary.

## Why QPACK Appears Here

The reason QPACK appears in an HPACK document is not that QPACK is an extension
of HPACK in the source tree. It is the next step in the same study question:
**how should HTTP header fields be represented efficiently when the surrounding
transport and protocol model changes?**

The important reading boundary is therefore:

```text
HTTP/2
  ↓
HPACK

HTTP/3
  ↓
QPACK
  ↓
QUIC streams / multiplexing
```

The two mechanisms should be compared at the conceptual boundary, not merged
into one implementation story.

## History

The known development path is:

```text
HPACK / QPACK study
        ↓
      QUIC
        ↓
TLS handshake / extension study
        ↓
   deep TLS study
        ↓
 QUIC packet / frame implementation
        ↓
   HTTP/3 integration
```

This is a reconstructed path from the development context currently available.
Exact chronology should be refined from CHANGELOG/SVN history. Unknown motivation
is not invented.

## Conceptual

### Header Field Representation

```text
Header Field
     │
     ├── known through table
     │       ↓
     │    indexed
     │
     └── otherwise
             ↓
          literal
```

### Tables

The Static Table is predefined and shared conceptually by both endpoints.
The Dynamic Table is communication state.

```text
             Table
          ┌────┴────┐
          ↓         ↓
       Static    Dynamic
                    │
             capacity / size
             ordering / entries
             insertion / eviction
```

The Dynamic Table is therefore protocol state, not merely a container.

### String Representation

Representation selection and string encoding are separate decisions.

```text
Header Field
     ↓
representation
  ├── indexed
  └── literal
          ↓
     string encoding
       ├── raw
       └── Huffman
```

## Structural

```text
                 HPACK
                   │
          ┌────────┴────────┐
          ↓                 ↓
       Encoder           Decoder
          │                 │
          └────────┬────────┘
                   ↓
              Table State
              ┌────┴────┐
              ↓         ↓
           Static    Dynamic
```

Current source anchors:

- `sdk/net/http/hpack/`
- `test/testcase/net/hpack/`
- HPACK Huffman wrapper/fixed RFC table: `sdk/base/encoding/http_huffman_coding.hpp/.cpp`
- HPACK Huffman known-answer tests: `test/testcase/net/hpack/testcase_huffman.cpp`
- Generic Huffman and chunked stream tests: `sdk/base/encoding/huffman_coding.hpp`, `test/testcase/encode/testcase_huffman.cpp`
- HTTP/2: `sdk/net/http/http2/`
- HTTP/2 tests: `test/testcase/net/http/`

Names are anchors; the conceptual structure above is the document's subject.

## Flow

### Encoding

```text
Header Fields
     ↓
Table lookup
  ┌──┴───────┐
  ↓          ↓
known      unknown
  ↓          ↓
indexed    literal
              ↓
        optional insertion
              ↓
        string encoding
          ┌───┴───┐
          ↓       ↓
         raw   Huffman
          └───┬───┘
              ↓
         Header Block
```

### Decoding

```text
Encoded Header Block
        ↓
Representation
   ┌────┴────┐
   ↓         ↓
 index     literal
   ↓         ↓
 table    name/value
 lookup      │
   └────┬────┘
        ↓
   table update
        ↓
   Header Field
```

### State

```text
Encoder                         Decoder
   │                               │
   │ table update                  │
   ├──────────────────────────────→│
   │ insertion / eviction          │
   ├──────────────────────────────→│
   └──────── same logical state ───┘
```

## Study & Verification

### Huffman

HPACK uses the fixed RFC 7541 code table exposed by `http_huffman_coding`, which derives from the generic `huffman_coding` class but does not learn a new table from each header block.

Anchors:

- `sdk/base/encoding/http_huffman_coding.hpp/.cpp` — fixed RFC 7541 table and symbol encode/decode.
- `test/testcase/net/hpack/testcase_huffman.cpp` — RFC 7541 Appendix B known-answer bytes and encode/decode round trips.
- `sdk/base/encoding/huffman_coding.hpp` and `test/testcase/encode/testcase_huffman.cpp` — generic learned/imported Huffman behavior and stream chunk-boundary checks.

### RFC 7541

RFC 7541 examples provide concrete reference points for representation,
table state, and encoded bytes.

Current HPACK testcase area:

- `test/testcase/net/hpack/`

The document records what the study verified rather than making testcase names
the narrative.

### Dynamic Table

The key study sequence is:

```text
insert → size update → capacity check → eviction → new index state
```

### Test Vector

```text
Header Fields
      ↓
    encode
      ↓
 expected bytes
      ↓
    decode
      ↓
Header Fields
```

A vector therefore connects conceptual behavior to concrete bytes.

## Status

| Area | State |
|---|---|
| Static Table | Implemented |
| Dynamic Table | Implemented |
| Header representation | Implemented |
| Encoder | Implemented |
| Huffman | Implemented / studied |
| RFC 7541 study | Present |
| HPACK test vector | Present |
| HTTP/2 relationship | Used by HTTP/2 implementation |

Detailed status should be rechecked against the source revision when this
document is synchronized with a newer edition.

---

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1132            │
│ Documented with GPT-6                │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
