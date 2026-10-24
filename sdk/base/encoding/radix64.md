## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Radix-64

## 1. Role

### Introduction

`radix64` implements the CRC/checksum and armor-oriented processing associated with RFC 4880 Radix-64. The payload alphabet and byte packing are reused from Base64 rather than implemented as a separate encoding.

## 2. Data Model

- `encoded` holds the Base64 representation of the payload.
- `crc` holds the Base64 representation of the three CRC-24 bytes.
- `decoded` receives the payload bytes during armor decoding.
- `crc24()` calculates the checksum over the original or decoded byte sequence.

The public names `radix64_encode`, `radix64_decode`, and the multiline aliases map to the Base64 APIs. Armor-specific validation is provided by `radix64_armor_encode()` and `radix64_armor_decode()`.

## 3. Behavior Model

### Armor encoding

```text
input bytes
   ├── Base64 encode ───────────────────► encoded payload
   └── CRC-24
         │
         ▼
      network-byte-order 32-bit value
         │ select the three checksum bytes
         ▼
      Base64 encode ────────────────────► checksum text
```

The encoder calculates CRC-24 over the original payload. It converts the checksum to network byte order and encodes the three checksum bytes, returning payload text and checksum text separately.

### Armor decoding and verification

```text
encoded payload ──► Base64 decode ──► decoded bytes
                                          │
                                          ▼
                                       CRC-24
                                          │
                              encode calculated checksum
                                          │
supplied checksum ────────────────────────┤
                                          ▼
                                      compare text
                                 ┌────────┴────────┐
                               equal             unequal
                                 │                  │
                              success     errorcode_t::mismatch
```

A successful Base64 decode is not sufficient: the checksum must also match. The checksum detects accidental corruption but is not a cryptographic integrity/authentication mechanism.

## 4. Relationships

- `sdk/base/encoding/base64.*` provides payload and checksum encoding.
- `sdk/base/basic/crc.cpp` implements `crc24()`.
- `test/testcase/encode/testcase_base64.cpp` covers RFC 4880 section 6.5 vectors, CRC-24 values, round trips, and section 6.6 ASCII-armored message processing.

## 5. References

- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880), Sections 6.5 and 6.6.
