# Hotplace Binary Construction Abstraction

## Source Baseline

- Source revision: 1106

## 1. Perspective

Hotplace contains code that directly constructs binary data in many different places.

Representative examples include:

- `sdk/io/basic/payload`
- `sdk/base/stream/binary_stream`
- `rfc2617_digest` for HTTP authentication
- binary parsing-table resource generation

These components do not share one common framework, and they should not be treated as three competing ways to solve exactly the same problem. It is useful to distinguish three roles:

1. **Layout description** — describe the fields and their relationships (`payload`).
2. **Sequential byte construction** — append and prefix values into a binary buffer (`binary_stream`).
3. **Protocol- or resource-specific construction** — turn protocol state or a defined resource layout into a wire representation (for example, a publisher or the parsing-table writer).

These roles can cooperate in one implementation. In particular, the parsing-table code uses `payload` to describe/read structured fields and `binary_stream` to emit the table efficiently. The choice of `binary_stream` for writing is an implementation choice, not evidence that the table has a different logical binary model.

This document reviews that recurring pattern.

---

## 2. The Simplest Problem: Construct Binary Data in Order

Binary protocol implementations repeatedly encounter layouts such as:

```text
field A
field B
length
payload
field C
...
```

Each field's byte representation has to be calculated and written to a buffer in order.

That is manageable for small structures, but the implementation quickly becomes verbose when there are many fields or when length encoding, endianness, and variable-length fields are mixed together.

Hotplace naturally developed several small abstractions to reduce this repetition.

---

## 3. `binary_stream`

`sdk/base/stream/binary_stream` can be viewed as a small tool for straightforward binary construction.

It is particularly convenient when a binary resource such as a parsing table has to be emitted as a sequence of values, especially when records are produced in loops and can be appended directly to a buffer:

```text
value 1
value 2
value 3
...
```

Conceptually:

```text
logical data
    ↓
binary_stream
    ↓
sequential binary writes
    ↓
binary buffer / file
```

The goal is not to create a large serialization framework.

> The goal is simply to make a binary layout readable as a sequence of writes in the source code.

---

## 4. `payload`

`sdk/io/basic/payload` describes a binary layout in terms of named members and their encoding/read-write behavior. It is not limited to network packets: the same field-oriented abstraction can describe structured binary resources, including the parsing-table header and records.

It treats the binary layout of a protocol packet as a payload abstraction, but its role is more generally to describe and process a sequence of binary fields.

Initially, its role was strongly associated with fixed-length binary payloads, but HTTP/2 and QUIC made variable-length representations increasingly important.

From the current perspective, it is therefore more accurate to view payload not simply as a:

> fixed-length packet buffer

but as:

> a common abstraction for binary payload/layout representations used by protocols.

---

## 5. Why Payload Matters

Binary representations of network protocol packets recur at multiple levels of hotplace's protocol implementations.

For example:

```text
TLS / DTLS
    ↓
record / handshake
    ↓
protocol fields
    ↓
binary payload
```

Or:

```text
HTTP/2 / QUIC
    ↓
frame / packet
    ↓
length / type / flags / data
    ↓
binary representation
```

If protocol code directly manages buffer offsets and lengths everywhere, higher-level protocol logic becomes tightly coupled to binary-layout logic.

The payload abstraction helps separate those concerns somewhat:

```text
protocol semantics
       ↓
payload/layout abstraction
       ↓
raw bytes
```

---

## 6. From Fixed-Length to Variable-Length

This part is useful when reconstructing hotplace's development path.

It is natural to begin by thinking of a binary payload as fixed-length:

```text
header | fixed body
```

Real protocols repeatedly introduce structures such as:

```text
header
  +
length
  +
variable payload
```

or:

```text
field
  +
encoded length
  +
field data
```

As QUIC introduced variable-length integers and packet/frame structures with variable sizes, the payload abstraction naturally moved toward representing more general binary layouts.

The evolution is therefore better understood as:

```text
simple binary payload
        ↓
real protocol requirements
        ↓
variable-length representation
        ↓
more general payload abstraction
```

rather than as a large framework designed in advance.

---

## 7. Another Form in HTTP Authentication

A similar pattern appears in HTTP authentication.

`sdk/net/http/auth/rfc2617_digest.*` calculates the values required by Digest authentication and constructs the corresponding HTTP authentication representation.

The important point is again not raw byte-buffer manipulation, but the connection between higher-level meaning and representation:

```text
authentication semantics
        ↓
digest calculation / fields
        ↓
HTTP representation
```

This is not the same abstraction as payload, but it demonstrates the same implementation approach: express the protocol meaning first, then assemble the required wire representation.

---

## 8. Fluent Construction

Hotplace HTTP test code also contains cases where a stream is used to construct values sequentially and the completed result is retrieved for later use.

Conceptually:

```text
construct
   ↓
append / write
   ↓
complete representation
   ↓
retrieve
   ↓
use as protocol data
```

The advantage is that the order of the binary representation closely follows the order of the source code.

In other words:

```text
write A
write B
write C
```

directly exposes the wire layout:

```text
A | B | C
```

That property is useful when reading and debugging binary protocols.

---

## 9. Binary Parsing-Table Generation: `payload` + `binary_stream`

The `.ptb` resource discussed in the parser evolution review illustrates how the first two roles cooperate. The logical layout includes a header and blocks such as the string table, terminals, productions, action table, and goto table.

On the read path, `binary_parsing_table` uses `payload` to describe and decode named fields and records. On the write path, it uses `binary_stream` to append values sequentially, prefix block sizes, and assemble each block before combining it into the final buffer.

```text
              binary parsing-table format
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       payload field layout       binary_stream
       / structured reading       / sequential writing
              │                         │
              └────────────┬────────────┘
                           ▼
                         .ptb
```

The writer could express the fields through `payload` as well. The implementation instead uses `binary_stream` for the write path because sequential appends are a little more efficient and fit the table-generation loop naturally. This is a choice of construction path, not a separate binary-format category: the table's logical layout remains the same.

This is not a parser algorithm itself. It is the mechanism used to produce and consume a binary artifact generated by the parser tooling.

Revision 1102 advanced the binary parsing-table format to revision 2; revision 1104 advanced it again to revision 3. A generated parser resource is a serialized interface between the table generator and runtime reader, not just an opaque data file. Grammar changes, table layout/version, generated `.ptb` artifacts, and build-time packaging must remain aligned.

---

## 10. This Is Not a Generic Serialization Framework

This pattern should not be confused with a general-purpose serialization framework.

The important idea in hotplace is not:

```text
object
  ↓
generic serializer
  ↓
automatically serialized object
```

It is closer to:

```text
code that knows the protocol/resource layout
             ↓
small construction abstraction
             ↓
fixed, intentional binary representation
```

The goal is therefore not to hide the meaning and layout of the binary format, but to make repetitive byte-level construction less tedious.

---

## 11. Why This Small Abstraction Is Interesting

Helpers of this kind are small enough to look insignificant at first.

But implementing several binary protocols repeatedly exposes the same concerns:

```text
length calculation
endianness handling
field append
variable-length value
buffer construction
final byte extraction
```

Wrapping these repeated operations in small abstractions allows higher-level code to focus more on protocol meaning.

This is why hotplace tends to develop several focused tools in different locations instead of merging everything into one large framework.

---

## 12. Why the Different Abstractions Should Not Be Merged

`payload`, `binary_stream`, and protocol-specific construction have related goals, but they play different roles. They are complementary rather than mutually exclusive categories.

```text
payload
    └─ field-oriented layout description and structured read/write

binary_stream
    └─ sequential byte construction into a binary buffer

protocol-specific construction
    └─ protocol semantics and boundaries (for example, publishers)

binary parsing table
    └─ payload for structured fields/read path
       + binary_stream for efficient sequential write path
```

Forcing these into one common serialization layer would distort hotplace's actual structure. But describing the parsing-table writer as `binary_stream` alone would also omit the role of `payload` in the same format's structured representation and reader.

The commonality described in this review is therefore not an implementation hierarchy but a set of **complementary construction roles**.

---

## 13. Evolution Revealed by HTTP/2 → QUIC

The protocol study path also helps explain the binary-construction pattern.

```text
HTTP/2
  ↓
binary frame representation
  ↓
QUIC
  ↓
packet / frame
  ↓
variable-length fields
  ↓
more flexible payload representation
```

QUIC uses fields of different sizes and variable-length encodings in both packets and frames.

Implementing such a protocol directly turns the question of convenient binary construction from a minor helper concern into a continuing engineering concern.

---

## 14. Construction Boundaries Inside Protocol Implementations

The publisher examples add one useful refinement to the binary-construction story.
The abstraction is not only about writing bytes conveniently; in protocol code, a construction component can mark the point where higher-level state becomes a concrete wire unit.

```text
semantic / protocol state
          │
          ▼
      construction boundary
          │
     ┌────┴─────┐
     ▼          ▼
 publisher   protocol-specific builder
     │          │
     └────┬─────┘
          ▼
      wire representation
```

`dtls_record_publisher` and `quic_packet_publisher` are useful examples of this pattern. They should not be collapsed into one generic serialization framework, because DTLS record construction and QUIC packet construction have different protocol semantics. What repeats is the architectural role: a focused component owns the transition from protocol state to a concrete wire-oriented unit.

This is also why the publisher pattern is more informative at the review level than a list of individual append/length APIs.

---

## 15. Relationship to Other Protocol Implementations

This pattern is not limited to one protocol.

Hotplace repeatedly encounters places where binary representation is required:

```text
TLS / DTLS
HTTP/2
QUIC
HTTP authentication
ASN.1 encoding
parser resource
```

The requirements differ by subsystem, so hotplace does not standardize everything around one binary builder.

Instead, each location gets a small abstraction sized to its actual need.

This also fits the project's broader implementation style:

> Rather than designing a large framework first, absorb recurring problems with small utilities as they appear in real implementations.

---

## 16. Related Code

### Base Stream

- `sdk/base/stream/binary_stream`
- small helper for sequential binary construction

### IO Basic

- `sdk/io/basic/payload`
- protocol binary payload/layout abstraction

### HTTP Authentication

- `sdk/net/http/auth/rfc2617_digest.*`
- Digest authentication representation

### Parser Resource

- `sdk/io/parser/binary_parsing_table`
- `test/tool/makeparsingtable`
- `.ptb` parsing-table generation
- `payload` describes and reads named fields/records; `binary_stream` is used for sequential table emission

### Related Tests

- HTTP protocol-construction tests
- parser parsing-table generation tests
- encode/packet-construction tests for the individual protocols

---

## 17. Current Status

Hotplace does not currently have one integrated binary serialization framework.

Instead, several small abstractions exist because different implementation problems require them:

```text
binary_stream
      │
      ├── simple sequential binary construction
      │
payload
      │
      ├── protocol binary layout
      │
protocol-specific builders
      │
      ├── HTTP authentication
      ├── TLS / DTLS
      └── QUIC
      │
resource writers
      │
      └── parsing table (.ptb)
```

The common thread is not an implementation hierarchy. It is the use of complementary small abstractions: `payload` for field-oriented layout and structured processing, `binary_stream` for efficient sequential byte emission, and protocol-specific components for semantic construction boundaries.

---

## 18. In One Sentence

Hotplace's binary construction approach can be summarized as:

> **Keep the logical binary layout visible, then choose a suitable implementation path for reading or writing it.**

`payload` and `binary_stream` are complementary tools rather than competing formats. The parsing-table implementation is a concrete example: `payload` expresses and reads the structured fields, while `binary_stream` emits them efficiently in sequence. The format is one; the construction paths can differ.
