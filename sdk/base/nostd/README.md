## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
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
| Binary and value | byte sequences, integer/floating-point serialization helpers, deferred values | Represent or transform values without tying them to one protocol |
| Ranges and sets | intervals, normalized range sets, string sets, runtime set facade | Represent membership and range constraints; used by higher-level constraint evaluators |
| Type and utility support | traits, key/value, exceptions, conversion and casting helpers | Shared compile-time and runtime support for templates and callers |

## 3. Behavior Model

The directory does not define one common ownership or execution model. Container invalidation rules, deferred-value completion, range normalization, and conversion behavior must be read from the individual implementation and focused note before relying on them.

### Representative operation flows

```text
encoded destination (std::string / binary_t / stream_t*)
  └─ encoder_stream_traits<T>
       ├─ trunc() when replacement is requested
       ├─ reserve() output capacity
       ├─ low-level encoder writes bytes
       └─ commit() reconciles reserved and written length

range or string constraints
  └─ range / range_set / string_set representation
       └─ ASN.1 constraint evaluator interprets membership and bounds

raw pointer from external API
  └─ custom::make_unique_with_deleter() / make_promise_on_destruction()
       └─ unique_ptr owns release responsibility
            └─ deleter runs at destruction unless ownership is released

deferred value
  └─ defer(name) ─► promise/future state
       └─ set_value(value) ─► fulfillment + cached value
            └─ value() ─► return cached/result value
```

These flows cross several utility families, but do not imply a shared base class or shared lifetime rule. In particular, `reserve()`/`commit()` is a destination-adapter protocol, range membership is interpreted by the consumer, and deferred values intentionally suppress some promise/future exceptions as described in their focused page.

The range/set facilities are more than general-purpose containers: ASN.1 constraint evaluation consumes them to represent and evaluate permitted numeric or string values. The exact constraint semantics remain the responsibility of the ASN.1 layer.

## 5. Relationships

### Focused source notes

- [Containers](containers.md) — sequence, tree, set and priority-queue structures
- [Binary utilities](binary.md) — byte sequences and integer/floating-point serialization helpers
- [Memory ownership](memory.md) — C++11-compatible unique ownership, custom deleters and raw-pointer adoption
- [Ranges](range.md) — intervals, range operations and range-oriented helpers
- [Bit set](bit_set.md) — bounded integer membership represented as bits
- [Runtime set facade](set.md) — runtime selection between numeric range and string set backends
- [Range set](range_set.md) — normalized numeric/ordered range operations
- [String set](string_set.md) — literal strings, string ranges, FROM and regex operations
- [Key/value](keyvalue.md) — lightweight key/value representation
- [Exceptions](exception.md) — project exception abstraction
- [Traits](traits.md) — type traits and encoding/formatting adapters
- [Utility helpers](utility.md) — conversion, casting and miscellaneous helpers
- [Deferred value](value.md) — value/future/promise-backed deferred values

- `sdk/io/asn.1/` — consumes range/set facilities in ASN.1 constraint evaluation.
- `sdk/base/stream/` — provides stream abstractions that may be used alongside byte-oriented helpers, but is a distinct component family.
- [`test/testcase/base/nostd/`](../../../test/testcase/base/nostd/README.md) — source-level examples and testcase coverage. The testcase overview owns assertions and verification notes; the focused SDK pages explain implementation details.

## 6. References

No external references are listed.
