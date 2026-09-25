# Payload — Protocol Field Layout and Binary Interpretation

**Edition 1 · Based on Revision 1084**

## Context

`payload` is a common binary field-layout layer used by protocol readers and writers. It sits below protocol objects such as HTTP/2 frames, TLS records/handshakes/extensions, and QUIC packets/frames, while remaining above raw byte containers and primitive endian conversion.

```text
protocol object
      │
      │ describes fields
      ▼
   payload
      │
      ├── field order
      ├── field width
      ├── length dependency
      ├── conditional presence
      └── encoded representation
      │
      ▼
 binary stream
```

The important role is not merely serialization. `payload` provides a compact way to describe enough of a protocol layout that the same description can participate in both reading and writing.

This makes it a useful point of convergence for otherwise different protocols:

```text
HTTP/2 frame ─┐
TLS record ───┤
TLS handshake ├──► payload / payload_member ───► bytes
TLS extension ┤
QUIC frame ───┤
QUIC packet ──┘
```

The protocol class still owns protocol semantics. `payload` owns the local binary layout needed to move between those semantics and bytes.

## Reading path

A first-time reader should approach `payload` from the protocol side rather than from its classes. The question is:

> **A protocol already knows what its fields mean. How does that field description become bytes, and how do bytes become those fields again?**

That gives the following path:

```text
protocol meaning
      ↓
field layout
      ↓
payload / payload_member
      ↓
wire bytes
```

The reverse path is equally important:

```text
wire bytes
      ↓
payload traversal
      ↓
field values
      ↓
protocol interpretation
```

This is why `payload` should not be read as a protocol parser by itself. It solves the **local binary layout problem**; the surrounding protocol still decides what the extracted fields mean, what state they change, and whether the resulting message is valid.

The reader can then follow three recurring patterns:

```text
fixed field
    → known width

length-dependent field
    → earlier field determines width

conditional / encoded field
    → protocol state or representation rules determine participation/encoding
```

These patterns explain most of the later HTTP/2, TLS, and QUIC examples in this document.

## History

The current `CHANGELOG.md` records the development milestones of HTTP/2, TLS, DTLS, QUIC, and related protocol work, but does not identify a separate milestone for `payload` itself. Therefore this document does not assign an origin revision or infer a development motivation from file dates.

What can be established from Revision 1084 is the present relationship: the module is shared infrastructure used throughout protocol readers and writers. Its history is consequently reconstructed here from current source relationships rather than an invented chronological narrative.

## Conceptual

### A payload is an ordered field layout

A `payload` is fundamentally an ordered sequence of `payload_member` objects.

```text
payload
  ├── member[0]
  ├── member[1]
  ├── member[2]
  └── ...
```

A member can represent a fixed-width integer, binary/string data, a bignumber, or a protocol-defined encoded value. The order in which members are registered is the order in which the layout is read and written.

The useful abstraction is therefore:

```text
protocol field description
          ↓
      payload_member
          ↓
     binary position
```

A member is not the protocol semantic object itself. It is a temporary field-level description used to interpret or construct the binary representation of that object.

### Size comes from four different sources

A field's space can be determined in several ways.

```text
field size
   ├── fixed by primitive type
   ├── explicitly reserved
   ├── referenced from another field
   └── delegated to payload_encoded
```

Fixed-width integers get their space from the underlying `variant`. `reserve()` assigns an explicit width. `set_reference_value()` makes one member's size depend on another member's value. `payload_encoded` delegates the representation to a protocol-specific encoder/decoder.

This distinction is the center of the module: protocol layouts frequently combine all four forms in one message.

### Length dependency is a relationship, not a special parser

Many wire formats use a length field followed by data of that length.

```text
+--------+--------------------+
| length | data               |
+--------+--------------------+
     │
     └──────────────► size(data)
```

`set_reference_value("data", "length")` expresses this relation without moving the length semantics into `payload::read()` itself.

A multiplier can be applied when the referenced count represents elements rather than bytes:

```text
count × element_size → field size
```

This allows the generic reader to consume layouts whose size is known only after an earlier member has been decoded.

### Conditional groups describe structural presence

Protocol flags often control whether several fields exist at all. `payload` models this with named groups.

```text
flag
  │
  └──► group enabled?
          ├── yes → fields participate in read/write
          └── no  → fields are skipped
```

A group can be selected directly by `set_group()`, or changed while reading through a `set_condition()` hook executed after a named member has been read.

This is more than output filtering: group state changes the active wire layout.

### One unknown-sized field can be inferred from the remainder

A binary/string/bignumber member can initially have no explicit size. During `read()`, such a member is deferred while known-sized members are accounted for. If exactly one unknown-sized active member remains, the reader assigns it the remaining bytes and performs another pass.

```text
input size
   - fixed fields
   - referenced fields
   - reserved fields
   = unknown field size
```

Example:

```text
padlen : 1 byte
body   : unknown
value  : 4 bytes
pad    : size = padlen
```

For a 12-byte input with `padlen = 3`:

```text
body = 12 - 1 - 4 - 3 = 4 bytes
```

This is a small layout-solving step rather than ordinary linear parsing.

The current implementation deliberately has a narrow rule: more than one unresolved unknown-sized member produces `bad_data`. An encoded field also cannot be deferred behind an unresolved unknown-sized field; the encoded representation must be readable at its position.

### Encoded values are an extension boundary

`payload_encoded` separates the generic layout engine from a protocol-specific variable representation.

```text
payload_member
      │
      └── payload_encoded
            ├── lsize()
            ├── value()
            ├── data()
            ├── read()
            └── write()
```

The concrete example in Revision 1084 is `quic_encoded`, which implements QUIC variable-length integer encoding and can also bind that length encoding to associated data.

This is important because QUIC's encoding is not modeled by adding QUIC branches to `payload`. Instead, the protocol-specific representation is injected through the generic encoded interface.

## Cross-Topic Boundary

`payload` is the boundary between **protocol-defined field meaning** and **binary field layout**. It is deliberately below protocol semantics and above raw byte movement.

```text
protocol
  │ owns meaning / state / validation
  ▼
payload
  │ owns field layout / size / representation
  ▼
bytes
```

This explains why the same payload mechanism can appear in HTTP/2, TLS, DTLS, and QUIC without making those protocols variants of one implementation. The shared part is the recurring binary-layout problem; the protocol-specific meaning remains outside the generic layer.

For QUIC in particular, `quic_encoded` is the handoff point where a protocol-specific representation enters the generic layout mechanism:

```text
QUIC semantic value
      ↓
quic_encoded
      ↓
payload_member
      ↓
QUIC wire bytes
```

The reverse direction reconstructs the semantic value before QUIC applies its own protocol rules.

## Structural

### `payload_member`

`payload_member` is the field unit. Its important state is:

```text
payload_member
  ├── _name       lookup identity
  ├── _group      conditional layout group
  ├── _bigendian  integer byte order
  ├── _vt         ordinary value
  ├── _ref        referenced length/count member
  ├── _refmulti   reference multiplier
  ├── _vl         payload_encoded implementation
  ├── _reserve    explicit field width
  └── _flags      reserve/state flags
```

Primitive integer constructors establish fixed-width members. Binary, string, and bignumber members can become fixed by reference or reservation during parsing. Encoded members delegate both size interpretation and data extraction to `payload_encoded`.

`write()` is correspondingly simple: encoded members delegate to their encoder; ordinary members serialize the `variant`, applying endian conversion when requested.

### `payload`

`payload` owns the ordered field collection and the relationships between fields.

```text
payload
  ├── _members       ordered layout
  ├── _members_map   name → member
  ├── _option        group → enabled/disabled
  └── _cond_map      member name → post-read hook
```

The ordered list is used for binary traversal. The name map supports relationships and value lookup. Group options control active members. Condition hooks allow an already-read field to affect the remaining layout.

The ownership model is also explicit: insertion through `operator<<` releases the incoming proxy/`unique_ptr`, and `_members` owns the resulting member until `clear()` or destruction.

### `payload_encoded`

`payload_encoded` is a polymorphic contract for representations whose encoded width cannot be described as a normal fixed-width `variant`.

Its interface separates:

- encoded-length size (`lsize`),
- decoded semantic value (`value`),
- optional associated data (`data`),
- binary reading/writing,
- access to the decoded `variant`.

`quic_encoded` uses the same contract in two forms:

```text
QUIC integer
    semantic uint64
        ↕
variable-length integer bytes
```

and:

```text
QUIC length + opaque data
    length encoding + bytes
            ↕
       one encoded member
```

The `_datalink` state in `quic_encoded` distinguishes those uses.

### Read-time layout resolution

`payload::read()` combines the previous concepts into one algorithm.

```text
for each active member
        │
        ├── encoded
        │     └── read immediately
        │
        ├── fixed / reserved
        │     └── read or account for known space
        │
        ├── referenced
        │     └── resolve referenced value → reserve → read
        │
        └── unresolved
              └── defer
```

If no unresolved field remains, parsing completes in one pass. If exactly one remains, its size becomes the unconsumed remainder and the layout is replayed so the deferred member can be read at the correct position.

The second pass is not a general backtracking parser. It is a bounded solution for one unknown segment surrounded by fields whose sizes can already be established.

### Conditional update after a field is read

`set_condition()` attaches a callback to a named field. `read()` invokes matching hooks immediately after that member is decoded.

```text
read member
    ↓
condition hook
    ↓
set_group(...)
    ↓
remaining members see new layout state
```

This matters for formats such as TLS/DTLS where an early discriminator changes the shape of the remaining header.

### Protocol reader/writer relationship

The concrete protocol classes generally use `payload` locally rather than retaining it as the protocol state object.

```text
read path
wire bytes
    ↓
local payload description
    ↓
member values
    ↓
protocol object state

write path
protocol object state
    ↓
local payload description
    ↓
payload::write()
    ↓
wire bytes
```

That boundary keeps the binary layout machinery reusable while allowing each protocol class to own validation, state transitions, cryptographic behavior, and higher-level semantics.

## Flow

### HTTP/2: flags select fields, length selects padding

`http2_frame_data` and `http2_frame_headers` show the layout model clearly.

For a DATA frame with padding:

```text
PADDED flag
    │
    └── enable padding group

Pad Length ─────────────► Padding size
Data        ─────────────► remaining body
Padding     ─────────────► referenced size
```

The data portion can be left unknown because the frame body size is already bounded by the surrounding HTTP/2 frame parser. `payload` subtracts the optional pad-length field and referenced padding from that bounded body to infer the data size.

HEADERS adds another independent optional group for PRIORITY fields. The same payload can therefore express two flag-controlled structural branches without adding those branches to the generic reader.

### TLS: fixed-width fields plus nested length-delimited vectors

TLS repeatedly uses fixed-width length fields followed by variable binary regions.

```text
length
   ↓
vector bytes
   ↓
protocol-specific nested parser
```

Examples appear across extensions, handshake messages, and records. `payload` handles the local binary boundary; the TLS class then interprets the extracted vector according to its own semantic rules.

TLS also demonstrates condition hooks. Record/version information can change which grouped fields are active, allowing TLS and DTLS layouts to share the same basic mechanism while retaining their different header shapes.

### QUIC: generic layout plus protocol-specific encoding

QUIC combines ordinary binary fields with QUIC variable-length integers.

```text
payload
  ├── ordinary member
  ├── quic_encoded integer
  ├── quic_encoded length+data
  └── ordinary binary remainder
```

`quic_frame_crypto`, ACK-related frames, stream-related frames, packet headers, and QUIC transport parameters use this pattern.

For example, QUIC transport parameters repeatedly read:

```text
Parameter ID      → quic_encoded(integer)
Parameter Value   → quic_encoded(length + bytes)
```

The generic `payload` traversal remains unchanged. Only the encoded field knows QUIC's variable-length representation.

### QUIC packet parsing also uses explicit reservation

Packet parsing sometimes knows a field width from cryptographic context rather than a preceding wire length. `reserve()` covers this case.

A packet reader can therefore combine:

```text
encoded length
+ unknown payload region
+ explicitly reserved AEAD tag
```

The reserved tag width is counted while the remaining packet payload is inferred from the bounded packet input.

### AEAD protection uses payload as binary layout glue

`tls_protection_encryption_aead.cpp` also uses `payload` while constructing/interpreting protection-related binary material. This is an important boundary: `payload` does not perform cryptography, but it can describe the exact byte layout consumed by cryptographic operations.

```text
protocol state
   ↓
field layout
   ↓
bytes used by AEAD processing
```

This reinforces the module's role as binary layout infrastructure rather than a protocol-specific parser.

## Study & Verification

### Core tests

The direct tests are:

```text
test/testcase/io/basic/testcase_payload.cpp
test/testcase/io/basic/testcase_payload_quic.cpp
```

`testcase_payload.cpp` exercises the core mechanisms rather than a single protocol:

- write and read symmetry,
- 24-bit and 48-bit integer fields,
- inferred unknown-size data,
- referenced lengths,
- conditional groups and hooks,
- DTLS-shaped data,
- bignumber payloads.

The group test is particularly useful because it demonstrates the full chain:

```text
header read
   ↓
condition hook
   ↓
group enable/disable
   ↓
length reference
   ↓
conditional data read
   ↓
selected-group write
```

`testcase_payload_quic.cpp` verifies the `payload_encoded` extension using `quic_encoded`, including RFC 9000 variable-length integer examples and length-prefixed opaque data.

### Cross-protocol verification surface

The Revision 1084 source shows `payload` in all of the following reader/writer families:

```text
sdk/net/http/http2/*
sdk/net/tls/protection/tls_protection_encryption_aead*
sdk/net/tls/quic/frame/*
sdk/net/tls/quic/packet/*
sdk/net/tls/quic/quic_encoded*
sdk/net/tls/tls/extension/*
sdk/net/tls/tls/handshake/*
sdk/net/tls/tls/record/*
```

This cross-protocol use is stronger evidence of the abstraction boundary than any individual example. The same small field-layout mechanism supports HTTP/2 flags and padding, TLS vectors and conditional layouts, and QUIC variable-length encoding.

### Source anchors

Core implementation:

```text
sdk/io/basic/payload.hpp
sdk/io/basic/payload.cpp
sdk/io/basic/payload_member.cpp
```

Representative protocol uses:

```text
sdk/net/http/http2/http2_frame_data.cpp
sdk/net/http/http2/http2_frame_headers.cpp
sdk/net/tls/tls/record/tls_record.cpp
sdk/net/tls/tls/handshake/tls_handshake_client_hello.cpp
sdk/net/tls/tls/extension/tls_extension_sni.cpp
sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.cpp
sdk/net/tls/quic/frame/quic_frame_crypto.cpp
sdk/net/tls/quic/packet/quic_packet_initial.cpp
sdk/net/tls/protection/tls_protection_encryption_aead.cpp
```

The module-local `sdk/io/basic/payload.md` is useful as an implementation note, but this study document treats source and tests as the authority for current behavior.

## Status

At Revision 1084, `payload` is an established shared binary-layout component rather than an isolated helper.

Its current model supports:

- ordered field composition,
- fixed-width integer handling including 24-bit and 48-bit protocol fields,
- endian-aware integer serialization,
- binary/string/bignumber members,
- explicit reservations,
- value-referenced field lengths with multipliers,
- conditional field groups,
- post-read condition hooks,
- inference of one unknown-sized active field from the bounded remainder,
- pluggable encoded fields through `payload_encoded`,
- symmetric use in protocol read/write paths.

The main semantic boundary is clear:

```text
payload
  owns binary field layout

protocol class
  owns protocol meaning and state
```

The most significant current constraints visible in the implementation are equally clear: unknown-size inference handles one unresolved active member, and encoded members are expected to be decodable in sequence rather than postponed behind an unresolved field. These are properties of the present layout algorithm, not protocol semantics.

The module therefore fits the project as a reusable **protocol payload reader/writer substrate**: small enough to remain generic, but expressive enough to capture the recurring field-layout patterns shared by HTTP/2, TLS/DTLS, and QUIC.

## Related topics

- [HTTP/2](../../http2/README.md) — frame layouts, flags, padding, and priority fields.
- [TLS](../../tls/README.md) — record, handshake, extension, and protection structures.
- [QUIC](../../quic/README.md) — variable-length integers, packet/frame layouts, and TLS integration.
- [Network Server](../../network_server/README.md) — the higher-level path from transport/session processing to protocol framing.

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1090            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
