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

# crc

## 1. Role

### Introduction

`crc.hpp` / `crc.cpp` provides checksum helpers used by the SDK where a CRC-style integrity check is part of a binary format or protocol representation.

The implementation is a small low-level utility in `sdk/base/basic`; it is not a general cryptographic primitive.

## 2. Data Model

### Inputs and result representation

Both helpers accept a pointer to an octet sequence and its length, and return the checksum in `uint32`. `crc32()` exposes a 32-bit result; `crc24()` masks the result to 24 bits. The implementation's algorithm parameters are fixed constants rather than caller-supplied state:

| Helper | Initial value | Polynomial | Output width / finalization |
|---|---:|---:|---|
| `crc32()` | `0xFFFFFFFF` | `0xEDB88320` | 32-bit result, bitwise complement |
| `crc24()` | `0x00B704CE` | `0x01864CFB` | Low 24 bits |

These parameters form the checksum contract; the generic name “CRC-24” alone does not identify a unique algorithm.

## 3. Behavior Model

### Per-byte checksum flow

`crc32()` XORs each input byte into the low end of the accumulator, applies eight reflected polynomial steps, then complements the accumulator. `crc24()` XORs each byte into bits 16–23, shifts left eight times while reducing with the 24-bit polynomial when bit 24 is set, then returns the low 24 bits. The implementation guards the `crc24()` loop for a non-null pointer and nonzero length; `crc32()` iterates over the supplied length directly, so callers must provide a valid byte range for nonzero lengths.

```text
octets + length
  ├─ crc32: init FFFFFFFF → XOR byte → 8 right-shift/reduce steps → complement → uint32
  └─ crc24: init 00B704CE → byte into high 8 bits → 8 left-shift/reduce steps → mask 24 bits
```

### Concrete caller path: OpenPGP Radix-64 armor

The SDK's Radix-64 armor encoder shows where the CRC primitive becomes part of a real format operation:

```cpp
ret = base64_encode(data, data_size, encoded);
if (errorcode_t::success != ret) {
    __leave2;
}

auto checksum = hton32(crc24(data, data_size));
ret = base64_encode((byte_t*)&checksum + 1, 3, crc);
```

The checksum is calculated over the original payload, converted to network byte order, and then the three checksum bytes are Base64-encoded separately from the payload. The decoder repeats the calculation over the decoded payload and compares the encoded checksum, returning `errorcode_t::mismatch` when it differs. This is a useful caller example because it connects the checksum parameters described above to the format's byte selection and validation path; it does not make CRC a cryptographic integrity mechanism.

Source: `sdk/base/encoding/radix64.cpp` (`radix64_armor_encode()` / `radix64_armor_decode()`).

When reviewing a change, verify polynomial, bit direction, initialization/finalization, and output width against the intended format.

A CRC detects accidental corruption according to its specified checksum scheme; it does not provide collision resistance or authenticity and must not be used as a cryptographic security primitive. No dedicated direct CRC testcase was identified in this revision's source tree, so verification should follow the Radix-64 consumer and distinguish end-to-end format coverage from a standalone `crc24()` unit test.

## 5. Relationships

- `crc24()` is consumed by Radix-64 encoding to supply its CRC-24 checksum; `crc32()` is a separate 32-bit checksum helper.

```text
base/basic/crc.cpp
       │
       ├── crc32(...)  ──► 32-bit checksum
       └── crc24(...)  ──► 24-bit checksum
                              ▲
                              │
                    base/encoding/radix64
```
- `crc24()` is a low-level checksum helper consumed by Radix-64-related encoding code.
- The encoding layer owns the format-specific decision about when and how to include the checksum.
- CRC is not a substitute for a cryptographic digest, MAC, or digital signature.
- The implementation is in `crc.hpp/.cpp`; `radix64.hpp` consumes CRC-24 together with Base64 armor. Validate the caller-visible checksum representation through the Radix-64 testcase under `test/testcase/base/encoding/`, rather than treating a checksum-only vector as proof of the full format contract.

## 6. References

- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880), Sections 6.5 and 6.6.
