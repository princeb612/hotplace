# IEEE 754 representation and conversion

`ieee754` handles the representation-level side of floating-point values: classification, bit-field extraction, and conversion between IEEE 754 binary formats.

This is deliberately separate from `floating_point`. `floating_point` is about exact decimal/rational arithmetic; `ieee754` is about the representation of native binary floating-point values.

## Scope

The implementation deals with the following representation widths:

- half precision (16-bit)
- single precision (32-bit)
- double precision (64-bit)

It can classify values and expose the sign, exponent, and mantissa information used by IEEE 754 representations.

## Value classification

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

## Representation fields

IEEE 754 values are interpreted through their fundamental fields:

```text
+---------+----------------+------------------+
|  sign   |    exponent    |    significand   |
+---------+----------------+------------------+
```

The exact field widths depend on the selected format. The implementation exposes exponent/significand-related information through its IEEE 754 helper functions.

## Format conversion

The implementation provides conversions including:

```text
float <-> fp16
fp32  <-> fp16
fp64  <-> fp16 / related native conversions
```

The source also provides helpers for converting values when a smaller representation is sufficient.

`ieee754_as_small_as_possible()` examines a native floating-point value and selects the smallest supported representation that can represent the value according to the implementation's conversion rules.

## Implementation

Main files:

- `sdk/base/system/ieee754.hpp`
- `sdk/base/system/ieee754.cpp`

The implementation is concerned with binary representation and conversion, not arbitrary-precision arithmetic.

## Tests

Primary test:

- `test/testcase/base/system/testcase_ieee754.cpp`

The testcase covers fp16/fp32/fp64 conversion as well as representation classification and special values.

## Relationship to `floating_point`

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

Use `floating_point` when exact decimal/rational arithmetic is the concern. Use `ieee754` when the binary representation or IEEE 754 classification of a native floating-point value is the concern.

## Status

This is a low-level system utility supporting representation inspection and floating-point format conversion. It is not intended to replace the exact arithmetic types documented in `floating-point.md`.
