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

# t_bit_set

## 1. Role

`t_bit_set<T>` represents membership over a bounded integral domain using a packed byte vector. The header comment specifically identifies ASN.1 BIT STRING as a motivation and notes that `std::bitset` alone does not match the intended interface.

## 2. Data Model

```text
configured low..high integer domain
             |
             v
     value - low offset
             |
             v
      byte index + bit
             |
             v
        binary_t storage
```

The configured domain is represented as a contiguous span of integer values packed into `binary_t` storage. The fixed lower and upper bounds determine the bit offset for each value.

## 3. Behavior Model

### Membership operations

The constructor fixes the low/high domain for the lifetime of the object. Each value is translated to an offset from the lower bound; the offset selects a byte and bit in the packed vector. The allocated storage is limited to 1 MiB, and larger requested domains throw the project exception with too_large_data.

- insert()/add() sets a bit; insert_range()/add(start,end) covers a range.
- erase()/subtract() clears one bit or a range.
- contains()/has() tests membership; an out-of-domain value returns false from has() and an error code from the lower-level add/subtract operations.
- reset()/clear() clears the stored membership without changing the configured domain.

This is a bounded integral set. It does not automatically grow its domain when an out-of-range value arrives.

## 5. Relationships

- `bit_set.hpp` implements the bounded bit-set representation, and `testcase_bitset.cpp` provides direct source-level coverage. ASN.1 BIT STRING is the motivating domain mentioned by the header; the ASN.1 layer owns its encoding and semantic constraints.

## 6. References

No external references are listed.
