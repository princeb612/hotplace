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

# IEEE 754 representation and conversion

## 1. Role

### Introduction

`ieee754` handles the representation-level side of floating-point values: classification, bit-field extraction, and conversion between IEEE 754 binary formats.

This is deliberately separate from `floating_point`. `floating_point` is about exact decimal/rational arithmetic; `ieee754` is about the representation of native binary floating-point values.

### Scope

The implementation deals with the following representation widths:

- half precision (16-bit)
- single precision (32-bit)
- double precision (64-bit)

It can classify values and expose the sign, exponent, and mantissa information used by IEEE 754 representations.

`long double` is not currently handled by the conversion/classification API. C++ does not require `long double` to use one universal storage format: its width, precision, and representation vary across compiler, runtime/library, ABI, and platform combinations. Treating it as a fixed IEEE binary format would require an explicit platform-specific contract; the current implementation limits concrete conversion support to the formats listed below.

## 2. Data Model

### Value classification

The implementation distinguishes cases such as:

- positive zero
- negative zero
- normal values
- positive infinity
- negative infinity
- NaN
- quiet NaN
- signaling NaN

The classification is useful when code needs to inspect a floating-point value according to its binary representation instead of relying only on ordinary arithmetic comparisons.

### Representation fields

IEEE 754 values are interpreted through their fundamental fields:

```text
+---------+----------------+------------------+
|  sign   |    exponent    |    significand   |
+---------+----------------+------------------+
```

The exact field widths depend on the selected format. The implementation exposes exponent/significand-related information through its IEEE 754 helper functions.

## 3. Behavior Model

### Format conversion

The implementation provides conversions including:

```text
float <-> fp16
fp32  <-> fp16
fp64  <-> fp16 / related native conversions
```

The source also provides helpers for converting values when a smaller representation is sufficient. `ieee754_as_small_as_possible()` examines a native floating-point value and selects the smallest supported representation according to the implementation's conversion rules.
## 5. Relationships

- This is a low-level representation utility, not a replacement for the exact arithmetic types documented in `floating_point.md`.
- `test/testcase/base/system/testcase_ieee754.cpp` — source-level coverage for fp16/fp32/fp64 conversion, representation classification, and special values.
### Relationship to `floating_point`

The two facilities solve different problems:

```text
                     sdk/base/system
                            |
             +--------------+--------------+
             |                             |
      floating_point                    ieee754
             |                             |
   exact decimal/rational        binary representation
             |                     classification/conversion
        bignumber                  fp16/fp32/fp64
```

Use `floating_point` when exact decimal/rational arithmetic is the concern. Use `ieee754` when the binary representation or IEEE 754 classification of a native floating-point value is the concern. The implementation is in `ieee754.hpp/.cpp`; `nostd/binary.hpp` uses its representation conversion, and `testcase_ieee754.cpp` covers classification/conversion cases.

## 6. References

No external references are listed.
