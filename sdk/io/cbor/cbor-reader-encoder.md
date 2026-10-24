## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# CBOR Reader and Encoder

## 1. Role

Describes conversion between encoded CBOR data and the project's object representation, including the direct value-to-binary encoding path.

## 2. Data Model

### Reader context

`cbor_reader` works with a `cbor_reader_context_t`. The implementation's context separates completed root objects from temporary construction state:

| State | Purpose |
|---|---|
| `roots` | Completed root object references retained by the reader context |
| `temp.indef` | Tracks open indefinite-length nesting |
| `temp.parents` | Current container/parent stack used while attaching parsed items |
| `temp.items` | Pending parsed items used by the construction path |
| `temp.tag_value`, `temp.tag_flag` | Temporary tag state while the next item is being formed |

The public context is opaque to callers. `open()` allocates it; `close()` clears retained roots and deletes it; `clear()` releases roots and clears the temporary queues.

### Major type and additional information

The first byte is split into the 3-bit major type and 5-bit additional-information field:

| Major type | Meaning |
|---:|---|
| 0 | Unsigned integer |
| 1 | Negative integer (encoded magnitude represents `-1 - n`) |
| 2 | Byte string |
| 3 | Text string |
| 4 | Array |
| 5 | Map |
| 6 | Tag |
| 7 | Simple value or floating-point value |

Additional-information values 24–27 introduce a following 1-, 2-, 4-, or 8-byte argument. Value 31 marks an indefinite-length form where that form is supported. These fields are parsing controls, not separate logical child objects.

### Encoder and output boundaries

`cbor_encode` has overloads for integer and floating-point types, byte/text strings, `variant`, simple values, and `cbor_object` instances. It writes to a caller-supplied `binary_t`. `cbor_publisher` is a higher-level output interface for publishing an object or reader result as binary or stream text.

## 3. Behavior Model

### Binary parse path

```text
open(context)
   │
parse(bytes)
   ├── clear prior roots and temporary construction queues
   ├── read initial byte: major type + additional information
   ├── consume argument bytes / string payload when present
   ├── dispatch by major type
   │     ├── scalar or simple value ──► create item
   │     ├── array/map ───────────────► establish container context
   │     ├── tag ────────────────────► retain tag for tagged item
   │     └── indefinite form ────────► track nesting until break
   └── push/insert items into parent containers and roots
```

The diagnostic-expression overload converts the supplied hexadecimal text to bytes and then uses the binary parse path. It is therefore a convenience input form for encoded bytes, not a separate diagnostic-notation parser.

The parser has explicit checks for some malformed payload boundaries and returns errors such as invalid parameter or bad format along the parse path. Do not infer from those checks that every truncated argument, malformed UTF-8 string, duplicate map key, or RFC-level semantic constraint is comprehensively validated.

### Binary encode path

```text
hotplace value / cbor_object
          │
          ▼
select overload / value type
          │
          ├── choose major type or simple-value code
          ├── choose compact additional-information width
          ├── write argument in network byte order when multi-byte
          └── append string or binary payload when applicable
          │
          ▼
       binary_t
```

For negative integers, the CBOR argument is based on `-1 - value`. Integer and length arguments use the shortest width selected by the relevant overload. The encoder also has specialized paths for floating-point representations, tags, and big numbers; do not treat every `variant` type as equivalent to a scalar integer.

### Publish and compare representations

The vector testcase reads encoded bytes, publishes the resulting value both as diagnostic text and as binary, and compares the published bytes with the original vector. It permits a diagnostic comparison in cases where equivalent floating-point values have distinct legal encodings (for example, Infinity encoded with different float widths).

```text
test vector bytes ─► reader.parse()
                          │
                          ▼
                      object tree
                       /       \
                      ▼         ▼
              publish binary  publish diagnostic
                      │         │
            compare bytes   compare notation when needed
```

This is the source-level test path described by `testvector_cbor.cpp`; this documentation update did not execute it.

### Practical use: compare a parsed value in two representations

The vector testcase parses encoded CBOR, then publishes the parsed value both as diagnostic notation and as encoded bytes. It compares the byte representation with the supplied vector; selected floating-point cases may instead compare diagnostic notation because equivalent values can have different encoded widths.

```cpp
cbor_reader reader;
cbor_reader_context_t* handle = nullptr;
ansi_string diagnostic;
binary_t encoded;

reader.open(&handle);
auto ret = reader.parse(handle, input);
if (errorcode_t::success == ret) {
    reader.publish(handle, &diagnostic);
    reader.publish(handle, &encoded);
    reader.close(handle);

    bool match = (encoded == base16_decode(input));
    if (!match) {
        match = (diagnostic == expected_diagnostic);
    }
    _test_case.assert(match, __FUNCTION__, "CBOR vector");
}
```

This pattern keeps three questions distinct: whether parsing succeeds, what diagnostic value the reader reconstructs, and what bytes the publisher emits. When adapting the code, ensure the reader context is closed on every exit path; the reduced snippet follows the testcase's successful-parse path rather than providing general-purpose cleanup.

## 4. Relationships
### Related source

- `cbor_reader.*` — parse context and major-type dispatch.
- `cbor_encode.*` — direct value/object-to-binary encoding.
- `cbor_publisher.*` — higher-level binary and stream publication.
- `cbor.hpp` — shared CBOR types and major/simple-type definitions.

### Related tests

- [`test/testcase/cbor/testvector_cbor.cpp`](../../../test/testcase/cbor/testvector_cbor.cpp) — encoded input → object → binary/diagnostic comparison.
- [`test/testcase/cbor/testcase_rfc7049.cpp`](../../../test/testcase/cbor/testcase_rfc7049.cpp) — direct encoder and object publisher expected-byte assertions.
- [`test/testcase/cbor/sample.cpp`](../../../test/testcase/cbor/sample.cpp) — sample construction and output.

## 5. References
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949), especially major types, additional information, and encoding considerations.
