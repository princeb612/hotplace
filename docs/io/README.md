# IO

## Context

`sdk/io` is the layer where the common foundation from `sdk/base` becomes **structured input/output processing**.

It is broader than operating-system I/O. The source combines several kinds of work that share the same underlying problem:

```text
data / bytes / text
        │
        ▼
  representation
        │
        ├── stream
        ├── payload
        ├── encoding
        └── structured data
              │
              ├── parser
              ├── ASN.1
              └── CBOR
```

This makes `sdk/io` an important middle layer between generic foundation facilities and higher protocol/security layers.

The build dependency is:

```text
sdk-base
   ↓
sdk-io
   ↓
sdk-crypto
   ↓
sdk-net
```

The key architectural point is that IO does not mean only `read()`/`write()` system calls. It contains mechanisms for moving data, describing binary layout, recognizing syntax, and—when the format itself has a semantic model—building structured objects that later layers can use.

For a reader, the useful question is therefore not whether a component is called
stream, payload, parser, or ASN.1. It is **which representation boundary that
component is responsible for crossing**.

## History

The current IO layer reflects several major development lines that accumulated over time:

- stream and system abstractions
- binary payload construction and parsing
- CBOR
- ASN.1
- lexical analysis and parsing
- compression/encoding support
- platform-specific stream and system handling

The historical record also shows that these areas were developed in support of higher-level protocol work. HTTP/2, TLS, QUIC, COSE/CBOR, and ASN.1 all required reusable representation and parsing mechanisms.

Recent Revision 1090 work is especially important for the parser side. ASN.1 is currently experimenting with an integrated CFG covering notation, module, parameterized constructs, and information object class. GLR application is under experimental validation, while `asn1_runtime` remains based on the LALR parser and loader integration is later work.

Therefore the IO history should be read as several converging processing paths rather than as one subsystem designed at once.

## Conceptual

The central role of IO is:

> **Move data between external representation and structured representation without forcing every higher layer to implement its own representation machinery.**

A useful model is:

```text
external data
     │
     ▼
┌─────────────────────────────┐
│           sdk/io            │
│                             │
│  stream / system            │
│       ↓                     │
│  bytes / payload            │
│       ↓                     │
│  parser / structured data   │
│       ↓                     │
│  semantic object            │
└─────────────────────────────┘
     │
     ▼
higher-level protocol / security
```

There are three related but distinct concerns.

### 1. Transporting and buffering data

Streams and system abstractions answer:

> How does data enter or leave the program?

This includes file streams and platform-specific implementations. Network transport itself belongs primarily to `sdk/net`, but IO provides reusable stream and system mechanisms.

### 2. Interpreting binary layout

Payload answers:

> Given structured fields, how are they represented as bytes?

This is where field width, ordering, length references, conditions, and encoded representations are handled.

The distinction is:

```text
stream
  = where/how bytes are moved

payload
  = how fields occupy those bytes

protocol
  = what those fields mean
```

This is why the payload layer can be reused by HTTP/2, QUIC, TLS and other binary protocols without becoming a protocol implementation itself.

### 3. Constructing structured data

Parser, ASN.1 and CBOR answer increasingly structured questions, but they do not all stop at the same boundary:

```text
bytes / text
     ↓
syntax
     ↓
structure
     ↓
semantic object
```

The important point is that these are different stopping points. A parser can stop at syntax structure, while ASN.1 can continue into a semantic runtime model. Protocol layers such as HTTP/2, TLS, or QUIC then interpret their own wire structures according to protocol rules.

## Reading path

A first-time reader can follow `sdk/io` through four questions:

```text
1. How do bytes/text enter and leave?
        ↓
2. How are fields represented on the wire?
        ↓
3. How is structured text recognized?
        ↓
4. When does structure become a semantic object?
```

These questions lead to different parts of IO:

```text
stream / system
      ↓
payload / encoding
      ↓
parser
      ↓
ASN.1 / CBOR / other structured formats
      ↓
higher-level protocol or application meaning
```

The path is not a mandatory dependency chain. It is a way to understand why the topics coexist in `sdk/io` and where each one stops.

## Structural

### Major areas

The Revision 1090 source tree contains these major IO areas:

```text
sdk/io
├── asn.1
│   ├── basic
│   ├── compiler
│   ├── loader
│   ├── resource
│   └── runtime
│
├── basic
│   ├── payload
│   ├── oid
│   └── zlib
│
├── cbor
│
├── parser
│
└── stream
```

There are also platform-specific source areas for stream, string, and system handling.

This tree should not be interpreted as a single inheritance hierarchy. These are different structured-data/IO concerns sharing the same SDK layer.

### Stream and system boundary

The stream side separates common interfaces from platform realization:

```text
IO stream abstraction
       │
       ├── Linux
       └── Windows
```

The same pattern appears in system and string/platform-specific facilities.

The architectural value is the same as the base portability boundary: higher layers can consume an IO abstraction without embedding platform-specific implementation choices into protocol logic.

### Payload

`payload` is the binary layout mechanism already documented as a cross-cutting foundation.

Its position inside IO is important:

```text
base representation
       ↓
      IO
       ↓
    payload
       ↓
binary protocol structures
```

A payload member can represent fixed-width, referenced-length, conditional, encoded, or otherwise constrained wire fields.

The important boundary remains:

```text
payload = representation/layout
protocol = semantics
```

For example:

```text
HTTP/2 frame
    ↓
frame field semantics
    ↓
payload
    ↓
bytes
```

and:

```text
QUIC packet
    ↓
packet/frame field semantics
    ↓
payload / encoded representation
    ↓
bytes
```

### Parser

The parser area contains:

```text
lexical_analyzer
lexical_context
lexical_token
cfg_grammar
lalr_parser
glr_parser
parse_tree
```

The conceptual pipeline is:

```text
source text
    ↓
lexical analysis
    ↓
tokens
    ↓
CFG
    ↓
LALR / GLR parser
    ↓
parse result / parse tree
    ↓
semantic construction
```

`parse_tree` is a structural representation of syntax. It should not be confused with the semantic object produced by a domain-specific consumer.

This distinction is particularly important for ASN.1.

### ASN.1

ASN.1 is one of the largest structured-data areas in IO:

```text
ASN.1 notation
      ↓
lexical analysis
      ↓
parser
      ↓
parse structure
      ↓
semantic construction
      ↓
asn1_runtime
      ↓
encode / decode / typed access
```

The ASN.1 implementation itself contains several semantic layers:

```text
asn.1
├── basic
│   ├── semantic
│   ├── structural
│   └── visitor
├── runtime
├── loader
├── compiler
└── resource
```

The distinction between structural and semantic representations matters:

```text
ASN.1 syntax structure
       ↓
AST / structural node
       ↓
semantic ASN.1 object/type
```

At Revision 1090 the parser study is still in transition. The integrated CFG is being validated through the GLR experiment, while `asn1_runtime` remains on the LALR path. The loader has not yet absorbed this experimental path.

### CBOR

CBOR is another structured-data path:

```text
CBOR bytes
   ↓
CBOR reader
   ↓
CBOR object/data model
   ↓
visitor / publisher
   ↓
application or COSE
```

CBOR is therefore different from payload.

```text
payload
  = general binary field layout

CBOR
  = a specific self-describing structured data format
```

The two can cooperate, but they solve different problems.

### Compression and utility processing

Utilities such as zlib and OID support live in IO because they operate on data representation needed by higher-level formats/protocols.

For example:

```text
HTTP content
    ↓
content encoding
    ↓
zlib
    ↓
decompressed representation
```

The same principle applies to OID handling in ASN.1-related processing.

These facilities should not be promoted to independent architectural layers unless their own semantics become large enough to justify it.

## Relationship to higher layers

The most useful view of IO is not a linear stack but several consumers of the same structured-data substrate.

```text
                       sdk/io
                         │
        ┌────────────────┼─────────────────┐
        │                │                 │
        ▼                ▼                 ▼
     payload           parser          structured data
        │                │              │       │
        │                ▼              ▼       ▼
        │              ASN.1           CBOR    utilities
        │                │              │
        └────────┬───────┴──────────────┘
                 ▼
          higher-level layers
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
       TLS      QUIC    COSE/JOSE
```

This explains why IO sits below both crypto and network in the build graph.

### IO → Crypto

Crypto needs bytes, streams, encoded representations, and structured key/material handling.

```text
sdk/base
   ↓
sdk/io
   ↓
crypto
```

The crypto layer adds cryptographic meaning; IO supplies representation and processing mechanisms.

### IO → Network

Network protocols repeatedly need binary framing:

```text
network session
      ↓
protocol structure
      ↓
payload / stream
      ↓
bytes
```

The network layer determines protocol semantics and state; IO supplies reusable representation mechanisms.

### IO → COSE / ASN.1

Security/data formats frequently cross these boundaries:

```text
ASN.1 ───────┐
             ├── structured representation
CBOR ────────┘
       │
       ▼
   COSE / JOSE
```

The format layer should not be confused with the cryptographic operation layer. CBOR, ASN.1, and payload describe/represent data; crypto gives data cryptographic meaning and operations.

## Flow

A general IO flow can be expressed as:

```text
external source
     │
     ▼
stream / buffer
     │
     ▼
representation
     │
     ├── payload ──────────► binary structure
     │
     ├── lexer/parser ────► syntax structure
     │
     ├── ASN.1 ───────────► semantic type/object
     │
     └── CBOR ────────────► data object
                              │
                              ▼
                     higher-level consumer
```

### Binary protocol path

```text
incoming bytes
      ↓
stream
      ↓
payload / protocol reader
      ↓
complete protocol structure
      ↓
protocol state
      ↓
application
```

### ASN.1 path at Revision 1090

```text
ASN.1 notation
      ↓
integrated CFG
      ↓
LALR parser             GLR = next experiment
      ↓
parse result
      ↓
ASN.1 publisher / semantic construction
      ↓
asn1_runtime
```

This is deliberately different from saying that GLR has replaced LALR or that the new loader path is already integrated.

### CBOR path

```text
CBOR encoded bytes
      ↓
reader
      ↓
CBOR object/data
      ↓
visitor / publisher
      ↓
COSE / application
```

## Study & Verification

IO is verified at several levels.

### Direct component verification

Individual stream, payload, parser, ASN.1, and CBOR facilities have focused tests or construction experiments.

### Protocol-driven verification

Higher-level protocol work exercises IO indirectly:

```text
HTTP/2
   ↓
frame representation
   ↓
payload
   ↓
IO
```

```text
QUIC
   ↓
packet/frame representation
   ↓
payload / encoding
   ↓
IO
```

```text
ASN.1
   ↓
notation / parser / semantic construction
   ↓
runtime encode/decode
   ↓
test vector
```

### Capture and replay

PCAPNG belongs to the observation/reproduction layer rather than IO itself, but replay ultimately exercises IO representations:

```text
PCAPNG
   ↓
captured bytes
   ↓
replay
   ↓
protocol reader
   ↓
IO representation
   ↓
protocol state
```

This is why IO changes can affect apparently unrelated TLS/QUIC/network tests.

## Status

At Revision 1090:

- `sdk/io` is established as the common structured-data and representation layer below crypto/network.
- Stream and platform abstractions provide reusable input/output mechanisms.
- `payload` provides a reusable binary layout mechanism for protocol structures.
- Parser infrastructure supports lexical analysis, CFG, LALR, GLR experimentation, and parse-tree construction.
- ASN.1 provides a substantial syntax → semantic-object pipeline. The integrated CFG now spans notation, module, parameterized constructs, and information object class, with GLR validation underway; the production runtime path remains LALR-based.
- CBOR provides a separate structured-data representation used by higher security/data layers.
- Compression and other representation utilities remain supporting facilities within IO.
- Platform-specific source realization remains below the common IO abstraction.
- Further file-by-file documentation would mostly inventory implementations rather than reveal a new architectural boundary.

The next useful deep dives, if needed, are individual topics rather than another broad `sdk/io` pass: **parser/GLR**, **ASN.1 semantic construction**, or **payload**.

## Related topics

- [Base](../base/README.md)
- [Payload](../io/payload/README.md)
- [ASN.1](../asn.1/README.md)
- [Crypto](../crypto/README.md)
- [Network Server](../network_server/README.md)
- [PCAPNG](../pcapng/README.md)
