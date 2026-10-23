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

# CBOR Object Model

## 1. Role

Describes the CBOR object tree and its concrete value, array, map, pair, string, and simple-value types.

## 2. Data Model

### Base object and shared state

The implementation represents one CBOR data item as a tree of `cbor_object` instances. The base object stores:

- `cbor_type_t` identifying the object's structural/value category;
- flags, including flags relevant to indefinite-length representation;
- an optional CBOR tag;
- reserved capacity metadata;
- shared-reference bookkeeping used by `addref()` and `release()`.

The base also defines the common `add()`, `accept()`, and `represent()` interfaces. Concrete subclasses provide the actual child relationships and representation behavior; the base implementations of `join()` and `represent()` are not generic container implementations.

### Concrete tree

```text
cbor_object
  ├── cbor_data       scalar and common hotplace values
  ├── cbor_simple     CBOR simple values
  ├── cbor_bstrings   byte-string container
  ├── cbor_tstrings   text-string container
  ├── cbor_array      ordered child collection
  └── cbor_map        collection of cbor_pair objects
                         ├── key object
                         └── value object
```

- `cbor_data` accepts common hotplace representations such as integer types, `bignumber`, `binary_t`, strings, floating-point values, and `variant`/`variant_t`.
- `cbor_array` represents an ordered collection of child objects.
- `cbor_map` groups entries as `cbor_pair` objects. Each pair retains separate key and value object references.
- `cbor_bstrings` and `cbor_tstrings` provide string-specific container forms, distinct from a single scalar byte/text string.
- `cbor_simple` represents CBOR simple values such as booleans and other simple-value codes.
- A tag is attached to the object via `tag()`; it is not merely metadata held by the reader after parsing.

The logical object hierarchy is not the same thing as one particular wire layout. Definite and indefinite-length encodings can describe logical arrays, maps, and strings without requiring the consumer to treat each encoded chunk as a separate application value.

## 3. Behavior Model

### Building and traversing a nested value

For a nested map/array item, the reader creates the relevant container object and attaches child objects as the encoded items are consumed. A map entry is represented by a pair containing its key and value; a nested array or map remains a child subtree rather than being flattened into a scalar.

```text
encoded nested item
       │ reader
       ▼
cbor_map
  ├── cbor_pair(key, scalar)
  └── cbor_pair(key, cbor_array)
                     ├── scalar
                     └── cbor_map ...
       │
       ├── object publication / binary representation
       └── diagnostic representation
```

Representation is dispatched through the object's `represent()` implementation. The concise and diagnostic visitors provide different output targets; they do not change the logical type or shape of the tree.

### Lifetime boundary

The base object exposes reference-count operations, and test/sample code commonly releases heap-created roots after publication. The root object's reference count does not by itself describe every external pointer's lifetime; callers must follow the ownership contract of the concrete container and any references they retain.

The vector-driven and RFC-oriented test sources contain nested structures and scalar cases that exercise this model. Their presence documents source-level coverage, not a claim that the tests were run during this documentation update.

## 5. Relationships

### Related source

- `cbor_object.*` — shared object boundary, tags, flags, and reference counting.
- `cbor_data.*`, `cbor_simple.*` — scalar and simple values.
- `cbor_array.*`, `cbor_map.*`, `cbor_pair.*` — container and map-entry structure.
- `cbor_bstrings.*`, `cbor_tstrings.*` — string-specific container forms.
- `cbor_publisher.*` — higher-level output from object structures.

### Related tests

- `test/testcase/cbor/testvector_cbor.cpp` and `testvector_cbor.yml` — vector-driven encoded/decoded cases.
- `test/testcase/cbor/testcase_rfc7049.cpp` — RFC-oriented scalar, tag, and container examples.
- `test/testcase/cbor/sample.cpp` — sample object construction and representation.

## 6. References

- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949), including the data-item model and Appendix A examples.
