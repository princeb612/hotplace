# CBOR Object Model

## Role

The CBOR implementation represents one CBOR data item as a tree of `cbor_object` instances.

The central design is:

```text
CBOR data item
      │
      ▼
 cbor_object
      │
 ├── scalar/simple data
 ├── byte/text strings
 ├── array
 ├── map
 └── map pair
```

This keeps CBOR structure separate from the binary encoding itself.

## Base object

`cbor_object` provides the common boundary for the object tree.

It carries:

- CBOR type
- flags
- optional semantic tag
- reference counting
- reserved capacity used while parsing
- child/object insertion
- visitor dispatch
- binary and diagnostic representation

Concrete objects derive from this base.

## Concrete types

The main object classes are:

- `cbor_data` — numeric, boolean, floating-point, null/undefined, byte/string-oriented scalar values
- `cbor_array` — ordered collection of CBOR objects
- `cbor_map` — collection of key/value pairs
- `cbor_pair` — one map key and value
- `cbor_bstrings` — byte string container
- `cbor_tstrings` — text string container
- `cbor_simple` — CBOR simple values

The distinction between `cbor_array` and `cbor_map` is structural, while `cbor_data` provides the value boundary.

## Maps

A map is represented as a collection of `cbor_pair` objects.

```text
cbor_map
   │
   ├── cbor_pair
   │     ├── key
   │     └── value
   ├── cbor_pair
   │     ├── key
   │     └── value
   └── ...
```

The implementation provides convenience `add()` overloads for common key/value combinations and nested maps/arrays.

## Indefinite-length data

CBOR supports both definite and indefinite-length forms.

The object model can represent the logical collection independently from whether the encoded input used an indefinite-length representation. Encoding/decoding details remain in the reader/encoder layer.

This is important for preserving the separation:

```text
logical CBOR object
       ≠
one specific binary layout
```

## Tags

`cbor_object` can carry a CBOR tag. Tag handling is therefore attached to the object boundary rather than implemented only as a reader-side annotation.

## Values and hotplace types

`cbor_data` accepts the project's common value representations, including:

- integer types
- `bignumber`
- `binary_t`
- strings
- floating-point values
- `variant` / `variant_t`

This lets CBOR reuse existing hotplace numeric and value abstractions instead of introducing a separate value system.

## Representation

Every object can be represented through:

- `represent(stream_t*)`
- `represent(binary_t*)`

Higher-level publication is provided by `cbor_publisher`.

## Tests

Primary tests:

- `test/testcase/cbor/testvector_cbor.cpp`
- `test/testcase/cbor/testcase_rfc7049.cpp`
- `test/testcase/cbor/sample.cpp`

The YAML vector file is:

- `test/testcase/cbor/testvector_cbor.yml`

## Related source

- `cbor_object.*`
- `cbor_data.*`
- `cbor_array.*`
- `cbor_map.*`
- `cbor_pair.*`
- `cbor_bstrings.*`
- `cbor_tstrings.*`
- `cbor_simple.*`
- `cbor_publisher.*`
