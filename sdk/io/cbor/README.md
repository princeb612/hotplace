## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source base : Revision 1132                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```

# CBOR

## 1. Role

The directory provides the CBOR value tree and conversion paths between encoded bytes, object values, and readable representations. It is a format-specific subsystem, not a wrapper around the generic grammar parser.

## 2. Data Model

The implementation has four cooperating boundaries:

| Boundary | Main types | Responsibility |
|---|---|---|
| Logical item | `cbor_object` and concrete subclasses | Hold one CBOR value or a container tree, including tags and flags |
| Binary input | `cbor_reader`, `cbor_reader_context_t` | Consume CBOR bytes and assemble root objects with temporary container state |
| Binary/diagnostic publication | `cbor_publisher` | `publish(object, binary_t*)` uses the concise visitor for CBOR bytes; `publish(object, stream_t*)` uses the diagnostic visitor for text |
| Visitor strategies | `cbor_visitor`, concise/diagnostic visitors | Implement binary and diagnostic traversal of an existing object tree |
| Direct binary encoding | `cbor_encode` | Encode hotplace values or CBOR objects without first invoking the reader |

The tree includes scalar/simple values, byte/text strings, arrays, maps and map pairs. A map is represented through `cbor_pair` objects; an array is an ordered collection. A tag belongs to the `cbor_object` boundary rather than being only a reader-side note.

## 3. Behavior Model

### Conversion paths

```text
CBOR bytes ──► cbor_reader ──► cbor_object tree
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                  cbor_publisher  concise visitor diagnostic visitor
                         │            │            │
                         └── binary ──┘            └── stream text

hotplace value / cbor_object ──► cbor_encode ──► CBOR bytes
```


### Follow one conversion path

1. **Read input.** `cbor_reader::parse` clears the previous parse roots, reads each initial byte's major type and additional-information field, and consumes any following integer/length bytes or payload.
2. **Build the tree.** The reader's push/insert logic uses temporary parent/item queues to connect parsed items into arrays, maps, and pairs. Tags and indefinite-length containers affect how items are attached.
3. **Choose an output.** `cbor_publisher` publishes the object tree to a binary buffer or stream. The concise visitor requests each object's binary representation; the diagnostic visitor requests its stream representation.
4. **Encode directly when appropriate.** `cbor_encode` can encode hotplace values and CBOR objects without first running a reader. It is the lower-level encoding boundary used by higher-level publication paths.

```text
binary input ─► parse state ─► logical object tree
                                   │
                      ┌────────────┴────────────┐
                      ▼                         ▼
               binary publication       diagnostic publication
                      │                         │
                 CBOR bytes                stream notation

hotplace value / object ─► cbor_encode ─► CBOR bytes
```

These outputs are different representations of the same logical item; diagnostic notation is not a wire encoding. Parsing a value tree and publishing it also does not by itself establish application-specific semantics such as COSE message validation.

The current reader is not a strict malformed-input validator. It checks byte/text payload lengths, but reads additional-information integer/float widths before verifying that those bytes remain; it also does not consistently propagate `push()` / `insert()` failures. Its context reset clears roots and parent/item queues but does not reset all temporary scalar state (`indef` depth and pending tag), so reuse after an incomplete/malformed parse can retain state. Do not infer hardened untrusted-input handling from the existence of `cbor_reader::parse()`.

## 4. Relationships
### Component documents

- [CBOR object model](cbor-object-model.md) — object/value representation and container structure.
- [CBOR reader and encoder](cbor-reader-encoder.md) — binary input, parse state, and binary output paths.
- [CBOR visitors](cbor_visitor.md) — binary and diagnostic representations of an existing tree.
- [RFC 8949 Appendix A examples](rfc8949-examples.md) — retained specification-oriented examples.

### Related areas

- `sdk/crypto/cose/` — COSE uses CBOR as its message encoding; application-level processing is a separate layer.
- `sdk/base/encoding/` — common encoding facilities.
- `sdk/base/system/` — `bignumber` and numeric representation used by CBOR values.

### Related tests

- [CBOR testcase sources and vectors](../../../test/testcase/cbor/) — vector-driven parse/publication checks, RFC-oriented encoding checks, and sample object construction.

## 5. References
- [RFC 7049 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc7049), the earlier specification used by retained examples.
- [RFC 8949 — Concise Binary Object Representation](https://www.rfc-editor.org/rfc/rfc8949), the current CBOR specification.
