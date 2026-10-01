# crc

`crc.hpp` / `crc.cpp` provides checksum helpers used by the SDK where a CRC-style integrity check is part of a binary format or protocol representation.

The implementation is a small low-level utility in `sdk/base/basic`; it is not a general cryptographic primitive.

## Relationship with encoding

One visible consumer is the Radix-64 implementation, where `crc24()` provides the CRC-24 checksum associated with the format.

```text
base/basic/crc
      |
      v
  crc24()
      |
      v
base/encoding/radix64
```

The separation keeps the checksum primitive in `base/basic` while the encoding layer applies it according to the format's rules.

## Related source

- `sdk/base/basic/crc.hpp`
- `sdk/base/basic/crc.cpp`
- `sdk/base/encoding/radix64.hpp`

## Related test/reference

Search the base/encoding test area for the current Radix-64/CRC coverage when changing this implementation.
