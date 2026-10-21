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

# Radix-64

## 1. Role

### Introduction

`radix64` implements the additional processing needed by RFC 4880 Radix-64 representations.

The Base64 conversion itself is reused from the existing Base64 implementation. Radix-64 adds CRC-24 and armor-oriented processing around that encoding.

## 2. Data Model

Radix-64 armor combines Base64-encoded payload bytes with a CRC-24 checksum representation. It reuses the existing Base64 alphabet and bit-packing rules rather than defining a separate encoding alphabet.

The basic `radix64_encode()` and `radix64_decode()` names alias the corresponding Base64 operations. The armor-specific entry points are `radix64_armor_encode()` and `radix64_armor_decode()`.


## 3. Behavior Model

### Armor processing

```text
binary data
    ├── Base64 encode ───────┐
    └── CRC-24 checksum ─────┴──► Radix-64 armor data
```

`crc24()` calculates the checksum. `radix64_armor_encode()` returns the encoded payload and CRC representation; `radix64_armor_decode()` decodes the payload and verifies the supplied checksum against a newly calculated value.

RFC 4880 sections 6.5 and 6.6 provide the executable reference for this format and are covered in `testcase_base64.cpp`.

### Tests

`test/testcase/encode/testcase_base64.cpp`

The testcase includes:

- RFC 4880 section 6.5 Radix-64 conversion vectors
- CRC-24 values
- encode/decode round trips
- RFC 4880 section 6.6 ASCII-armored message decoding

## 4. Relationships

- `sdk/base/encoding/base64.*` — provides the alphabet/bit packing used by Radix-64.
- `sdk/base/basic/crc.cpp` — `crc24()` computes the checksum appended by the Radix-64 armor format.
- `test/testcase/encode/testcase_base64.cpp` — includes source-level Radix-64 vectors for the combined Base64-plus-checksum representation.

## 5. References

- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880), Sections 6.5 and 6.6.
