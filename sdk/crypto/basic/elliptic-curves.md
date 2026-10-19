## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Elliptic Curves

## 1. Role

This document identifies the module or reference topic represented by this file.

## 2. Model

#### Classification of Elliptic Curves
- Finite Field
  - Prime Field
    - Prime Field Curve (Fp)
      - y^2 = x^3 + ax + b mod p
      - P-256, P-384, P-521, ...
  - Binary Field
    - Binary Field Curve (F2m)
      - y^2 + xy = x^3 + ax^2 + b
      - B-163, B-233, B-283, K-163, K-233, ...
- Curve Form
  - Weierstrass
    - Weierstrass Curve
      - y^2 = x^3 + ax + b
  - Edwards
    - Edwards Curve
      - x^2 + y^2 = 1 + (d x^2 y^2)
      - Ed25519, Ed448
  - Montgomery
    - Montgomery Curve
      - By^2 = x^3 + Ax^2 + x
      - curve25519, curve448 (X25519, X448)
- Special Curve
  - Koblitz
    - Koblitz Curve
      - K-163, K-233, ...

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

See the referenced testcase source files for concrete examples. A source reference alone does not prove runtime execution.

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
