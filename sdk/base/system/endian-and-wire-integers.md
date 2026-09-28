# Endian and wire-format integers

`sdk/base/system` contains small integer/byte-order utilities used when a protocol field does not match a native C++ integer width.

## Endianness

`endian.hpp` provides:

- `is_big_endian()` / `is_little_endian()`
- `hton16`, `hton32`, `hton64` and the corresponding `ntoh*`
- `hton128` / `ntoh128` when the compiler provides `uint128`
- `convert_endian<T>()`

The implementation is template based rather than tied only to the platform socket APIs. Multi-byte values are transformed by swapping half-width pieces, while one-byte values are left unchanged.

## Custom-width integers

`uint.hpp` defines `t_uint_custom_t<TYPE, N>` and concrete types such as `uint24_t` and `uint48_t`.

The important point is that these are **wire-format widths**, not native arithmetic types:

```text
uint24_t : 3 bytes -> uint32
uint48_t : 6 bytes -> uint64
```

The conversion helpers are:

- `b24_i32()` / `i32_b24()`
- `b48_i64()` / `i64_b48()`

Both validate the input buffer and reject values that cannot fit in the target width.

## Protocol relationships

The source comments explicitly identify protocol uses:

- `uint24_t`: TLS handshake length, HTTP/2 frame length, ASN.1 certificate length
- `uint48_t`: DTLS record sequence

This makes the utility particularly useful in the parser/protocol layers where a field is specified as an exact number of network-order octets.

## Tests

`test/testcase/base/system/testcase_endian.cpp` checks host/network conversion and endian detection, including 64-bit and optional 128-bit values.

The custom-width integer implementations are exercised indirectly by protocol code and should be documented alongside the protocol users when their concrete wire layout matters.
