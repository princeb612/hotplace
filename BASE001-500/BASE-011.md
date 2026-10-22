# BASE-011 — floating_point extreme exponent gaps

- **Status:** Open — arithmetic boundary behavior needs analysis
- **Area:** `sdk/base/system/floating_point`
- **Basis:** Revision 1107 targeted source review; no numerical boundary tests were run during the documentation pass.
- **Source entry points:** [floating_point.cpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/system/floating_point.cpp), [floating_point.md](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/system/floating_point.md)

## Background

The earlier review found a `MAX_PRECISION = 1024` fallback associated with large exponent differences. The open question is whether this is an intentional bounded-precision policy or whether some paths lose sign, magnitude, or cancellation behavior unexpectedly. Establish the type's intended contract before calling it a defect.

## What is known

The historical source note identifies a bounded fallback for large exponent gaps. Both signs of the exponent difference and both addition and subtraction need examination. No mathematical comparison or boundary test was performed during the documentation pass.

## Analysis path

```text
operands (sign, significand, exponent)
              |
              v
       compare exponent gap
              |
              +--> ordinary alignment path
              |
              +--> large-gap fallback
                         |
                         v
                combine and normalize
                         |
                         v
                     result
```

## Questions

1. Where is the 1024 threshold applied, and what value is substituted or truncated?
2. Is the representation intended to be exact, bounded precision, or experimental?
3. What happens for positive versus negative exponent differences?
4. Are addition and subtraction consistent under operand reversal and sign changes?
5. What happens around the threshold for cancellation, opposite signs, and zero?
6. Is discarding a small operand an intended rounding policy, and is it documented?

## Next steps

Trace alignment and normalization, then reason through boundary cases before writing tests. A trusted arithmetic result can be used as a diagnostic comparison, not as an automatic requirement that this experimental type duplicate every native floating-point property. Document intentional limits; propose a fix only if behavior contradicts the intended contract.

## History

- **Revision 1107:** Large exponent-gap behavior was marked for mathematical and source verification.
- No source change or numerical test run recorded.
