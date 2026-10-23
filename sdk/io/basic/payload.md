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
# I/O Payload

## 1. Role

`sdk/io/basic/payload.*` provides a small declarative binary-payload description layer.

The caller describes a binary message as an ordered list of `payload_member` objects and can then use the same description for both encoding and decoding.

```text
payload
  ├── payload_member
  │     ├── fixed-size integer
  │     ├── binary / string / stream
  │     ├── uint24 / uint48 / uint128
  │     ├── bignumber
  │     └── payload_encoded
  │
  ├── group selection
  ├── length/reference relationships
  └── condition hooks
```

This is intended for protocol fields whose binary layout is known from the surrounding message structure, without introducing a separate schema language.

## 2. Data Model

### `payload`: ordered layout and indexes

A `payload` owns an ordered sequence of `payload_member*` entries. Insertion through `operator<<` transfers ownership of each member to the payload; the sequence controls wire order. A name-to-member map supports `select(name)`, length-reference setup, and value retrieval without changing that order.

The other persistent state has separate jobs:

| State | Meaning |
|---|---|
| `_members` | Ordered members traversed by read/write |
| `_members_map` | Name lookup index into the same member objects |
| `_option` | Current enabled/disabled value for each named group |
| `_cond_map` | Hooks keyed by the name of a field; hooks can update group state after that field is read |

The list is the serialization order; the map is an index, not an alternative ordering.

### `payload_member`: value plus field metadata

Each member stores its value in a `variant` and carries the metadata that determines how that value participates in the layout:

| Field/property | Meaning |
|---|---|
| `_name`, `_group` | Optional lookup name and conditional group name |
| `_bigendian` | Whether integer serialization applies the endian-conversion flag |
| `_vt` | Current scalar, binary, string, stream, or big-number value |
| `_ref`, `_refmulti` | Pointer to a length/reference member and multiplier for unit-based lengths |
| `_vl` | Optional `payload_encoded` implementation for a specialized field format |
| `_reserve`, `_flags` | Explicitly reserved field width and flag indicating that the reservation is active |

Fixed-width integers derive their normal field width from the variant type. Variable-size fields can obtain a width from a reference member or an explicit reservation. For a referenced field, the configured multiplier lets a length count units larger than one byte, such as a count of 16-bit values.

### `payload_encoded`: extension contract

`payload_encoded` separates a protocol-specific variable-length representation from the generic field sequence. Its interface exposes:

- `lsize()` and `value()` for the in-memory field's encoded-prefix width and represented value;
- `data()` and `write(target)` for its data and serialization;
- stream-based `lsize(stream, size)`, `value(stream, size)`, and `read(stream, size, pos)` for parsing;
- `get_variant()` for access to the decoded value through the common value representation.

The payload layer can therefore place a specialized field among ordinary members without understanding that field's protocol-specific encoding. QUIC's encoded integer path is an example of this extension boundary.

### Group state and length references

A member's group label associates it with a named condition. The payload stores group enablement separately, so changing a group can include or exclude the corresponding fields without rebuilding the ordered member list.

A length reference is a pointer relationship between two members. For example, if `padlen` stores 3 and `pad` refers to `padlen`, the field metadata describes a three-byte `pad` field. The reference relationship does not itself encode or update the length field; it supplies sizing information to the payload read/write path.

## 3. Behavior Model

### Size queries and their meaning

`get_space()`, `get_capacity()`, and `get_reference_value()` answer different questions; callers should not treat them as interchangeable:

- `get_space()` estimates the field's contribution to layout traversal. For an encoded member it reports `lsize()`, the encoded prefix width exposed by that implementation.
- `get_capacity()` reports the currently occupied/capacity-oriented size used by `payload::size_occupied()`.
- `get_reference_value()` returns the value used when another member refers to this member; an encoded field can supply that value through `payload_encoded::value()`.

The exact interpretation of a specialized field's prefix and value belongs to its `payload_encoded` implementation.

### Build the layout, then write in member order

```text
construct payload_member values
          │
          ▼
payload::operator<<
  ├─ append pointer to ordered _members
  ├─ index named member in _members_map
  └─ payload takes ownership
          │
          ▼
configure group state / length references / condition hooks
          │
          ▼
payload::write(binary_t&)
  ├─ visit members in insertion order
  ├─ skip members whose group is disabled
  └─ member.write(target)
       ├─ ordinary value ─► variant::to_binary()
       │                    └─ endian flag if requested
       └─ encoded value ───► payload_encoded::write()
```

`write(binary_t&)` appends each enabled field to the supplied buffer. The overload taking an explicit set of group names additionally filters named groups: ungrouped fields remain eligible, and a grouped field is written only when its group is enabled and included in the requested set.

### Read known-width and referenced fields

The input is parsed against the same ordered description. The read path keeps an offset into the original byte buffer and processes enabled members in order.

```text
payload::read(base, size, pos)
          │
          ├─ reject null base / exhausted starting position
          ▼
visit each enabled member
  ├─ encoded member
  │    └─ delegate read() to payload_encoded; advance by consumed pos
  ├─ fixed-width or reserved member
  │    ├─ check that the expected width fits
  │    └─ decode value / advance offset
  ├─ member with length reference
  │    ├─ obtain reference value × multiplier
  │    ├─ check input boundary and reserve that width
  │    └─ decode field / advance offset
  └─ otherwise
       └─ record as an unknown-width member
          │
          ▼
resolve unknown-width members
  ├─ none ─► parsing is complete
  ├─ exactly one ─► assign remaining bytes to that member
  │                 and replay the ordered read to establish final offsets
  └─ more than one ─► bad_data
          │
          ▼
commit caller's pos only when return status is success
```

The single-unknown-field rule is what makes a layout such as `header | data | fixed trailer` inferable: once the other fields' widths are known, the remaining bytes determine `data`'s width. Two unreferenced, unknown-width fields would be ambiguous, so this path returns `bad_data`.

### Conditional fields: decode a discriminator before later fields

A condition hook is registered against the name of a member. After that member is read, the hook receives the payload and the member and may update group state. Subsequent members consult that state before consuming bytes.

```text
read header / discriminator
          │
          ▼
invoke hook registered for header name
          │
          ├─ set_group("groupA", condition A)
          └─ set_group("groupB", condition B)
                    │
                    ▼
        later fields check group state
          ├─ disabled ─► skip without consuming bytes
          └─ enabled ──► parse at current offset
```

The hook runs after the named field has been read, so it can inspect the decoded value. This is a sequential layout mechanism: group decisions affect later fields, not fields that have already been traversed.

### Bounds and failure boundaries

- A null input base returns `invalid_parameter`; a starting position at or beyond the input size returns `no_data`.
- If a fixed, reserved, or referenced field cannot fit in the remaining buffer, the payload read path returns `fragmented`.
- More than one unresolved unknown-width member returns `bad_data`.
- The caller's `pos` is updated to the final offset only when the overall payload read status is `success`.
- Member decoding handles the byte representation for the member's variant type; specialized encoded members own their own parser and consumed-byte count.

### Source-level examples

The canonical reference example is `padlen | data | value | pad`, where `pad` refers to `padlen). The encoded input `03 64 61 74 61 00 00 10 00 70 61 64` supplies a three-byte pad and a fixed 32-bit value; `data` is the one unresolved field and is assigned the remaining four bytes after the known fields are accounted for.

The test sources cover write/read round trips, group selection, reference-sized fields, 24-bit and 48-bit integers, big-number values, and the `payload_encoded` extension used by QUIC. Test existence establishes source-level coverage; it does not by itself establish a runtime execution result.

## 5. Relationships
### Relationship with higher layers

```text
protocol implementation
        |
        v
     payload
        |
   +----+----+
   |         |
 fixed    encoded field
 fields   (protocol-specific)
```

It is used by higher-level protocol implementations such as HTTP/2, TLS-related structures, DTLS-related structures and QUIC code.

### Implementation source navigation

- `sdk/io/basic/payload.hpp`
- `sdk/io/basic/payload.cpp`
- `sdk/io/basic/types.hpp`
- `sdk/io/system/types.hpp` — `payload_encoded` integration types
- `sdk/base/basic/variant.hpp`
- `sdk/base/system/bignumber.hpp`
