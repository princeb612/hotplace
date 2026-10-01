# Exact floating-point arithmetic

`floating_point` is hotplace's abstraction for arithmetic that needs an exact decimal or rational representation rather than the approximation semantics of native `float`/`double`.

The implementation is built from three related types:

```text
                    floating_point
                     /          \\
          decimal_float       rational_float
                |                    |
         mantissa x 10^exp       numerator / denominator
                \\                  /
                 \\                /
                    bignumber
```

## Components

### `decimal_float`

Represents a decimal value as a `bignumber` mantissa and a base-10 exponent.

```text
value = mantissa x 10^exponent
```

This representation is useful when decimal precision is important. Decimal expressions such as `0.1`, `0.2`, `1e8`, and `-0.00123` can be retained without converting them through binary floating-point first.

### `rational_float`

Represents a value as an exact numerator/denominator pair of `bignumber` values.

Examples include:

```text
1/2
1/3
355/113
22/7
```

The representation is normalized so that arithmetic and comparison can operate on the exact rational value.

### `floating_point`

`floating_point` provides the common public abstraction. It can hold either decimal or rational representation and performs arithmetic while preserving an exact representation where possible.

A string containing `/` is interpreted as a rational expression; other numeric expressions are interpreted as decimal values.

## Arithmetic behavior

The implementation supports:

- addition
- subtraction
- multiplication
- division
- comparison
- string formatting
- conversion to rational representation

Decimal operands remain decimal when the operation can be represented in the decimal form. Mixed decimal/rational operations use the rational representation.

Division by zero is rejected. Decimal division that is not exactly representable as a decimal result can therefore become a rational result.

The decimal implementation uses `bignumber::pow10()` and a bounded precision adjustment when aligning decimal exponents during addition/subtraction.

## Why this exists

The important distinction is between **exact decimal/rational arithmetic** and native binary floating-point arithmetic.

For example, the tests intentionally exercise:

```text
0.1 + 0.2   = 0.3
0.1 + 1/3   = 13/30
1/2 + 1/3   = 5/6
```

Large decimal values are also tested, including arithmetic around `1000000000000000.1`, where retaining the decimal representation is part of the purpose of the type.

This is therefore not intended as a general replacement for `float` or `double`. It is a separate exact-arithmetic facility built on top of `bignumber`.

## Implementation

Main headers:

- `sdk/base/system/floating_point.hpp`
- `sdk/base/system/decimal_float.hpp`
- `sdk/base/system/rational_float.hpp`

Implementation files:

- `sdk/base/system/floating_point.cpp`
- `sdk/base/system/decimal_float.cpp`
- `sdk/base/system/rational_float.cpp`

The arithmetic ultimately relies on `bignumber` for arbitrary-width integer operations.

## Tests

Primary tests:

- `test/testcase/base/system/testcase_floatingpoint.cpp`
- `test/testcase/base/system/testvector_floatingpoint.cpp`
- `test/testcase/base/system/testvector_floatingpoint.yml`

The testcase covers decimal/rational construction and arithmetic, while the YAML-driven test vector covers a broader set of add/subtract/multiply/divide cases.

## Relationship to other system types

```text
bignumber
   |
   +-- decimal_float
   |      \
   |       +-- floating_point
   |
   +-- rational_float
          /
         /
```

`bignumber` supplies the integer foundation; `floating_point` combines decimal and rational forms into a higher-level arithmetic interface.

## Status

This is an implementation-specific exact-arithmetic utility in `sdk/base/system`. It should be understood together with `bignumber`, rather than as a general floating-point library.
