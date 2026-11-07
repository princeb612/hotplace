## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1123                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# nostd

## 1. Role

`sdk/base/nostd` is hotplace's C++11-oriented STL-style utility layer. It provides project-owned containers, value/range abstractions, binary helpers, traits and utility code used by higher-level SDK modules. The name signals a project-owned alternative to selected standard-library-style facilities, not a claim that every component replaces a corresponding `std` type.

## 2. Data Model

### Component families

| Family | Main facilities | Implementation role |
|---|---|---|
| Containers | sequence, tree, set and priority-queue structures | General-purpose storage and access patterns |
| Binary and value | byte sequences, integer/floating-point serialization helpers, named value wrapper | Represent or transform values without tying them to one protocol |
| Ranges and sets | intervals, normalized range sets, string sets, runtime set facade | Represent membership and range constraints; used by higher-level constraint evaluators |
| Type and utility support | traits, key/value, exceptions, conversion and casting helpers | Shared compile-time and runtime support for templates and callers |

## 3. Behavior Model

The directory does not define one common ownership or execution model. Container invalidation rules, value-wrapper semantics, range normalization, and conversion behavior must be read from the individual implementation and focused note before relying on them.

### Representative operation flows

```text
Base16 / Base64 destination
  └─ encoder_stream_traits<T>
       ├─ trunc() when replacement is requested
       ├─ reserve() grows logical output size
       ├─ low-level encoder writes into the reserved tail
       └─ commit() trims an unused tail after success

Huffman destination
  └─ encoder_stream_traits<T>
       ├─ preempt() provides a capacity hint (or no-op)
       └─ push() appends each emitted output unit

range or string constraints
  └─ range / range_set / string_set representation
       └─ ASN.1 constraint evaluator interprets membership and bounds

component-specific pointer handling
  └─ custom::make_unique_with_deleter() / make_promise_on_destruction()
       └─ caller-selected deleter manages the adopted resource
```

These flows cross several utility families, but do not imply a shared base class or shared lifetime rule. In particular, Base16/Base64 reserve/commit and Huffman preempt/push are distinct output protocols. Pointer helpers are caller-selected facilities, not a directory-wide ownership policy. The `t_value<T>` type is only a value/name holder; it does not provide deferred evaluation.

The range/set facilities are more than general-purpose containers: ASN.1 constraint evaluation consumes them to represent and evaluate permitted numeric or string values. The exact constraint semantics remain the responsibility of the ASN.1 layer.

## 4. Relationships

### Focused source notes

- [Containers](containers.md) — sequence, tree, set and priority-queue structures
- [Binary utilities](binary.md) — byte sequences and integer/floating-point serialization helpers
- [Memory ownership](memory.md) — C++11-compatible ownership helpers and a localized experimental low-memory transfer investigation
- [Ranges](range.md) — intervals, range operations and range-oriented helpers
- [Bit set](bit_set.md) — bounded integer membership represented as bits
- [Runtime set facade](set.md) — runtime selection between numeric range and string set backends
- [Range set](range_set.md) — normalized numeric/ordered range operations
- [String set](string_set.md) — literal strings, string ranges, FROM and regex operations
- [Key/value](keyvalue.md) — lightweight key/value representation
- [Exceptions](exception.md) — project exception abstraction
- [Traits](traits.md) — type traits, Base16/Base64 reserve/commit, Huffman preempt/push, and formatting adapters
- [Utility helpers](utility.md) — conversion, casting and miscellaneous helpers
- [Named value](value.md) — value storage with optional name and value-based comparison

- `sdk/io/asn.1/` — consumes range/set facilities in ASN.1 constraint evaluation.
- `sdk/base/stream/` — provides stream abstractions that may be used alongside byte-oriented helpers, but is a distinct component family.
- [`test/testcase/base/nostd/`](../../../test/testcase/base/nostd/README.md) — source-level examples and testcase coverage. The testcase overview owns assertions and verification notes; the focused SDK pages explain implementation details.

## 5. References

No external references are listed.
