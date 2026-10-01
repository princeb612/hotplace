# I/O Payload

## Role

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

## Encoding and decoding

A payload is built in field order:

```cpp
payload pl;
pl << new payload_member(..., "length")
   << new payload_member(..., "data")
   << new payload_member(..., "value");

pl.write(binary);
```

The same description can be populated from an input buffer:

```cpp
pl.read(binary);
```

The important design point is that the field description is reused for both directions.

## payload_member

`payload_member` stores one field's value and metadata.

Supported representations include:

- `uint8`, `uint16`, `uint24_t`, `uint32`, `uint48_t`, `uint64`, and `uint128` where available
- `binary_t`
- `std::string`
- `stream_t`
- `bignumber`
- `payload_encoded`

A member can also carry:

- a name
- a group name
- byte-order information
- a reference to another member
- a repeat/multiple value
- a reserved size

The value itself is held through `variant`, so the payload layer does not need a separate field class for every scalar type.

## Variable-length fields

A central feature is a field whose size is determined by another field.

For example:

```text
padlen  : uint8
...
pad     : binary, length = padlen
```

The relationship is registered with:

```cpp
pl.set_reference_value("pad", "padlen");
```

During decoding the known `padlen` value allows the otherwise variable-size `pad` field to be inferred.

A `multiple` parameter is also available for references when the encoded length is expressed in units larger than one byte.

## Groups and conditions

Members may belong to named groups.

```cpp
pl.set_group("pad", true);
pl.write(binary);

pl.set_group("pad", false);
pl.write(binary);
```

This allows optional portions of a protocol message to be selected without rebuilding the payload description.

Groups can also be controlled by a hook associated with another field:

```text
header value
    |
    v
condition hook
    |
    +---- enable group A
    +---- enable group B
```

This is used by the tests for conditional protocol layouts.

## payload_encoded

`payload_encoded` is the extension point for a field whose encoding is not represented by a simple fixed `variant` value.

Its purpose is to let a specialized encoder calculate and write the field representation while still participating in the surrounding `payload` sequence.

This is particularly relevant to protocol-specific variable-length encodings. QUIC uses this mechanism through its own encoded payload implementation.

## Protocol examples

The direct tests exercise the generic mechanism with layouts such as:

```text
uint8 padlen
binary data
uint32 value
binary pad[padlen]
```

and with 24-bit / 48-bit integers.

`testcase_payload_quic.cpp` separately exercises QUIC integer encoding through the payload extension mechanism.

The payload layer is therefore generic, while protocol-specific encodings remain outside `sdk/io/basic`.

## Relationship with higher layers

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

## Tests

- `test/testcase/io/basic/testcase_payload.cpp`
  - write/read round trips
  - groups and conditional groups
  - reference-sized fields
  - uint24 / uint48 handling
  - bignumber fields
- `test/testcase/io/basic/testcase_payload_quic.cpp`
  - QUIC integer encoding
  - `payload_encoded` integration

## Related source

- `sdk/io/basic/payload.hpp`
- `sdk/io/basic/payload.cpp`
- `sdk/io/basic/types.hpp`
- `sdk/io/system/types.hpp` — `payload_encoded` integration types
- `sdk/base/basic/variant.hpp`
- `sdk/base/system/bignumber.hpp`
