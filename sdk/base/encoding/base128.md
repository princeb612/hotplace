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

# Base128

## 1. Role

`base128` encodes a non-negative numeric value into a variable-length sequence of 7-bit groups. Each byte's high bit indicates whether another byte follows. ASN.1 object identifier (OID) serialization is one consumer of this primitive.

The API offers fixed-width and arbitrary-precision paths. The supported overloads are not all symmetric conversions, so callers should select them according to the value representation they need.

## 2. Data Model

### Values and byte ranges

| Input/output form | Purpose |
|---|---|
| `uint64` | Encode or decode a value within the fixed-width range. |
| `bignumber` | Encode or decode a larger integer without narrowing it to `uint64`. |
| `byte_t* + size` | Supplies the available encoded byte range or a big-endian input value, depending on the overload. |
| `binary_t` | Holds encoded bytes or the byte representation returned by an overload. |
| `pos` | Caller-owned cursor identifying the next byte to decode. |


## 3. Behavior Model

The pointer-based decoder advances `pos` as it consumes bytes, so a caller can decode consecutive values from a larger buffer without first slicing it into separate arrays.

### Encoding

The fixed-width and `bignumber` encoders first determine how many 7-bit groups are needed. They then write the groups from most significant to least significant into the appended output range. Every byte except the final byte has its high bit set to signal continuation.

```text
integer value
    │ determine group count
    ▼
split into 7-bit groups
    │ set continuation bit on every non-final group
    ▼
append Base128 bytes to binary_t
```

The byte-input overload constructs a `bignumber` from the supplied byte range before encoding. This is a numeric conversion path, not a byte-for-byte encoding of the original input.

### Decoding one value

The pointer-based decoder consumes bytes starting at `pos`. For each byte, it shifts the accumulated value by seven bits and adds the low seven payload bits. It stops when it encounters a byte with the continuation bit clear.

```text
stream, size, pos
       │
       ▼
read next byte and advance pos
       │
       ▼
value = (value << 7) | (byte & 0x7f)
       │
       ├── continuation bit set ──► read next byte
       └── continuation bit clear ─► success
```

The `uint64` path checks malformed/overlong input and reports `bad_data` when the available input ends before a terminating byte. The `bignumber` path has a maximum-byte guard to bound processing. Invalid parameters and malformed encodings are distinct from a successfully decoded value.

## 5. Relationships

- `sdk/io/asn.1/` consumes Base128 continuation-byte encoding for OID arcs. ASN.1 owns OID semantics; this directory owns the numeric representation.
- `base128.hpp/.cpp` declare and implement the public overloads.
- `test/testcase/encode/testcase_base128.cpp` provides fixed vectors and large-number source-level coverage.


## 6. References

No external references are listed.
