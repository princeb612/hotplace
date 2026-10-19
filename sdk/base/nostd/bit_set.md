## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# t_bit_set

## 1. Role

`t_bit_set<T>` represents membership over a bounded integral domain using a packed byte vector. The header comment specifically identifies ASN.1 BIT STRING as a motivation and notes that `std::bitset` alone does not match the intended interface.

## 2. Model

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

Construction normalizes the supplied bounds and allocates storage for the span. The implementation rejects allocations larger than its fixed 1 MiB threshold by throwing `exception(errorcode_t::too_large_data)`. Values outside the configured domain return `out_of_range` from `add`/`subtract`; `has` returns false for out-of-range values.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source tests

`testcase_bitset.cpp` exercises membership, insertion/removal and byte output. The base report records a `bitset` group with 8 pass and 11 expt entries; preserve that classification rather than interpreting `expt` as an ordinary pass.

## 5. Relationships

- `sdk/base/nostd/bit_set.hpp`
- `test/testcase/base/nostd/testcase_bitset.cpp`
- `sdk/io/asn.1/` — ASN.1 BIT STRING is the motivating domain mentioned by the header

## 6. References

- Packed bit-vector representation; the precise semantics are defined by `t_bit_set` and its tests.
