# Base128

`base128` provides a variable-length base-128 representation used by protocol-oriented binary formats.

The implementation is particularly relevant to ASN.1 OID encoding, where an OID component is represented using base-128 continuation bytes.

## Main operations

The API supports three practical forms:

```text
uint64
  ↕
base128

binary value
  ↕
base128

bignumber
  ↕
base128
```

The decode operation receives a byte stream, its size, and a mutable position. This allows a base-128 value to be decoded as part of a larger binary structure rather than requiring the value to occupy the entire input buffer.

## bignumber support

The `bignumber` overloads allow values larger than the normal fixed-width integer types to use the same representation.

This is useful for protocol data where the encoded integer width is determined by the value rather than by a C++ integer type.

The implementation therefore connects two hotplace components:

```text
bignumber
    │
    ▼
 base128
    │
    ▼
 protocol binary representation
```

## Tests

`test/testcase/encode/testcase_base128.cpp`

The testcase covers:

- known base-128 values and byte vectors
- stream decoding with a position index
- binary input/output
- large values represented by `bignumber`
- round-trip encode/decode

The fixed vectors are useful as compact examples of the encoded representation.

## Related source

- `sdk/base/encoding/base128.hpp`
- `sdk/base/encoding/base128.cpp`
- `sdk/base/system/bignumber.hpp`
- `test/testcase/encode/testcase_base128.cpp`

The implementation is also used by ASN.1 code for OID-related encoding.
