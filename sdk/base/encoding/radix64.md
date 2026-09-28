# Radix-64

`radix64` implements the additional processing needed by RFC 4880 Radix-64 representations.

The Base64 conversion itself is reused from the existing Base64 implementation. Radix-64 adds CRC-24 and armor-oriented processing around that encoding.

```text
binary data
    │
    ├── Base64 encode
    │
    └── CRC-24
          │
          ▼
     Radix-64 armor data
```

## CRC-24

`crc24()` calculates the checksum used by the Radix-64 format.

`radix64_armor_encode()` returns both the Base64-encoded data and its CRC representation.

`radix64_armor_decode()` decodes the data and verifies the supplied CRC representation against a newly calculated checksum.

The basic Radix-64 names such as `radix64_encode()` and `radix64_decode()` are aliases of the corresponding Base64 operations. The armor functions are the part that adds Radix-64-specific behavior.

## RFC examples

The main executable reference is RFC 4880 sections 6.5 and 6.6, both covered in `testcase_base64.cpp`.

This is intentionally kept as a separate document because Radix-64 is more than another Base64 alphabet: it adds checksum and ASCII-armor semantics.

## Tests

`test/testcase/encode/testcase_base64.cpp`

The testcase includes:

- RFC 4880 section 6.5 Radix-64 conversion vectors
- CRC-24 values
- encode/decode round trips
- RFC 4880 section 6.6 ASCII-armored message decoding

## Related source

- `sdk/base/encoding/radix64.hpp`
- `sdk/base/encoding/radix64.cpp`
- `sdk/base/encoding/base64.*`
- `test/testcase/encode/testcase_base64.cpp`
