# CBOR Reader and Encoder

## Role

`cbor_reader` and `cbor_encode` provide the binary boundary of the CBOR implementation.

```text
CBOR binary
    │
    ▼
cbor_reader
    │
    ▼
cbor_object tree
    │
    ▼
cbor_encode
    │
    ▼
CBOR binary
```

The reader also accepts a diagnostic-expression path used by the test/sample layer.

## Reader

`cbor_reader` manages a `cbor_reader_context_t` while parsing.

The main entry points include:

- `open()` / `close()`
- `parse()` from binary data
- `parse()` from a diagnostic expression
- `publish()` into an object tree or binary/stream representation
- `push()` / `pop()` for parser construction
- `insert()` for object insertion
- `clear()`

The parser builds the hierarchical object representation as it encounters CBOR major types and their payloads.

## CBOR major types

The reader follows the CBOR major-type model:

```text
0  unsigned integer
1  negative integer
2  byte string
3  text string
4  array
5  map
6  tag
7  simple / floating-point
```

The first byte carries both the major type and the additional-information/control field. Additional bytes are consumed when the encoded value requires a larger integer or length representation.

## Definite and indefinite lengths

The implementation recognizes the indefinite-length forms for:

- byte strings
- text strings
- arrays
- maps

These use the CBOR break marker to terminate the logical sequence.

The reader therefore has to maintain container context while processing nested data.

## Encoder

`cbor_encode` converts hotplace values and `cbor_object` structures into CBOR binary.

Its overloads cover:

- signed/unsigned integers
- floating-point values
- byte strings
- text strings
- `variant`
- CBOR objects
- simple values
- tagged objects

The encoder also handles the CBOR additional-information encoding used for lengths and integer values.

## Object publication

`cbor_publisher` provides a higher-level publishing boundary:

```text
cbor_object / reader context
          │
          ▼
   cbor_publisher
      ├── binary_t
      └── stream_t
```

This keeps callers from having to operate the low-level encoder directly for common object-tree publication.

## Test relationship

The main implementation evidence is under:

- `test/testcase/cbor/testvector_cbor.cpp`
- `test/testcase/cbor/testcase_rfc7049.cpp`
- `test/testcase/cbor/sample.cpp`

The test vectors provide encoded/decoded CBOR examples while the RFC-oriented testcase exercises the older RFC 7049 reference material retained by the project.

## Related source

- `cbor_reader.*`
- `cbor_encode.*`
- `cbor_publisher.*`
- `cbor.hpp`
