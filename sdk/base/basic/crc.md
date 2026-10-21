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

## 3. Behavior Model

### Checksum contract

CRC behavior is defined by the algorithm implemented in `crc.cpp` and by the caller's format requirements. When reviewing a change, verify the polynomial and initialization/finalization choices in the code rather than relying on the generic term “CRC-24”.

A CRC detects accidental corruption according to its specified checksum scheme; it does not provide collision resistance or authenticity and must not be used as a cryptographic security primitive. No dedicated direct CRC testcase was identified in this revision's source tree, so verification should follow the Radix-64 consumer and distinguish end-to-end format coverage from a standalone `crc24()` unit test.

## 4. Relationships

- `crc24()` is a low-level checksum helper consumed by Radix-64-related encoding code.
- The encoding layer owns the format-specific decision about when and how to include the checksum.
- CRC is not a substitute for a cryptographic digest, MAC, or digital signature.
- The implementation is in `crc.hpp/.cpp`; `radix64.hpp` consumes CRC-24 together with Base64 armor. Validate the caller-visible checksum representation through the Radix-64 testcase under `test/testcase/base/encoding/`, rather than treating a checksum-only vector as proof of the full format contract.
