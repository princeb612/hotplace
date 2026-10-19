## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# crc

## 1. Role

### Introduction

`crc.hpp` / `crc.cpp` provides checksum helpers used by the SDK where a CRC-style integrity check is part of a binary format or protocol representation.

The implementation is a small low-level utility in `sdk/base/basic`; it is not a general cryptographic primitive.

## 2. Model

### Algorithms

`crc.cpp` implements two checksum helpers:

- `crc32()` uses the reflected IEEE 802.3 polynomial `0xEDB88320`, initializes to `0xFFFFFFFF`, processes each byte bitwise, and complements the final value.
- `crc24()` initializes to `0x00B704CE`, uses polynomial `0x01864CFB`, processes bytes into the high 8 bits of the running checksum, and returns the low 24 bits.

These details are taken from the implementation and matter when comparing values with an external CRC implementation: polynomial, bit direction, initialization, final XOR, and output width must all match.

### Relationship with encoding

The Radix-64 implementation is a visible consumer of `crc24()`, which supplies the CRC-24 checksum associated with that format.

```text
base/basic/crc.cpp
       │
       ├── crc32(...)  ──► 32-bit checksum
       └── crc24(...)  ──► 24-bit checksum
                              ▲
                              │
                    base/encoding/radix64
```

## 3. Important behavior and lifetime

### Checksum contract

CRC behavior is defined by the algorithm implemented in `crc.cpp` and by the caller's format requirements. When reviewing a change, verify the polynomial and initialization/finalization choices in the code rather than relying on the generic term “CRC-24”.

A CRC detects accidental corruption according to its specified checksum scheme; it does not provide collision resistance or authenticity and must not be used as a cryptographic security primitive.

## 4. Example from the source tests

### Trace the format consumer

No dedicated CRC testcase was identified under `test/testcase/base/encoding/` in this revision's source tree. The implementation can still be followed through its direct caller: Radix-64 encoding uses `crc24()` when the format requires the checksum.

For an end-to-end check, compare the produced Radix-64 output with a known vector and verify the checksum portion independently. Do not describe this as a direct unit test of `crc24()` unless a dedicated test is added.

## 5. Relationships

- `crc24()` is a low-level checksum helper consumed by Radix-64-related encoding code.
- The encoding layer owns the format-specific decision about when and how to include the checksum.
- CRC is not a substitute for a cryptographic digest, MAC, or digital signature.

## 6. References

### Related source and consumer tests

- `sdk/base/basic/crc.hpp`
- `sdk/base/basic/crc.cpp`
- `sdk/base/encoding/radix64.hpp`
- Search the Radix-64 encoding testcase under `test/testcase/base/encoding/` when validating the caller-visible checksum representation.

The relevant test should validate the complete format behavior as well as any low-level checksum vector available in the source.

