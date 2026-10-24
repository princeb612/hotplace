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

### Concrete caller path: ASN.1 named-bit value construction

The ASN.1 value layer uses the bounded bit set to collect selected non-negative named-bit values before appending the packed bytes to its output:

```cpp
asn1_native_int_t minvalue = *evalues.begin();
asn1_native_int_t maxvalue = *evalues.rbegin();
t_bit_set<asn1_native_int_t> bs(minvalue, maxvalue);

for (const auto& item : evalues) {
    bs.add(item);
}

binary_t temp = bs.get();
bin.insert(bin.end(), bs.unused_bit());
bin.insert(bin.end(), temp.begin(), temp.end());
```

The ASN.1 layer determines the active value domain and which named values are present. `t_bit_set` maps those values to bits and exposes the packed storage plus the number of unused bits in the final octet. ASN.1 then emits the unused-bit count before the bytes, as required by the surrounding BIT STRING representation. The bit set does not itself encode the ASN.1 tag/length or validate the schema's named-bit rules.

Source: `sdk/io/asn.1/basic/asn1_value.cpp`.

## 5. Relationships

- `bit_set.hpp` implements the bounded bit-set representation, and `testcase_bitset.cpp` provides direct source-level coverage. ASN.1 BIT STRING is the motivating domain mentioned by the header; the ASN.1 layer owns its encoding and semantic constraints.

## 6. References

No external references are listed.
