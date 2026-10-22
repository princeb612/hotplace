## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1106                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto Advisor Testcases

## 1. What

This directory contains source-level tests for the metadata and lookup interface implemented in [`sdk/crypto/advisor`](../../../../sdk/crypto/advisor/README.md). The tests focus on consistency of advertised features and resource mappings, not on implementing or benchmarking cryptographic primitives.

## 2. How

### Procedure: inspect registered feature availability

1. Construct or access the crypto advisor under the active OpenSSL/provider configuration.
2. Query the feature groups exposed by the test, including cipher/digest and the JWA/JWE/JWS/COSE/curve mappings.
3. Record the status returned for each queried feature and print the aggregate inventory for diagnosis.
4. Interpret the inventory as metadata/availability evidence. It does not execute each primitive or validate encryption, digest or signature output.

### Procedure: verify curve aliases

1. Query the advisor with the names `P-256`, `prime256v1` and `secp256r1`.
2. Resolve each name to its curve hint.
3. Assert that each resolved hint reports the expected NID, 415.
4. The source prints a wider curve table for inspection, but only the explicit alias assertions provide direct equality checks.

### Procedure: cross-check cipher resource metadata

1. Iterate the registered cipher hints.
2. Derive the scheme value from each hint's algorithm and mode, then compare it with the registered scheme field (the low 16 bits used by this mapping).
3. Look the hint up again by its fetch name and derive the scheme from the looked-up algorithm/mode.
4. Compare that result with the registered scheme as well.
5. Treat these as internal mapping-consistency checks. They do not invoke encryption/decryption or compare known-answer ciphertext.

## 3. Evidence

### Source-level coverage

**1. Feature availability**

~~~text
advisor enumerates cipher / digest / JWA / JWE / JWS / COSE / curves
  -> each callback derives success vs not_supported from feature/spec
  -> record availability status
  -> separately print aggregate feature inventory
~~~

The output is a metadata availability check against current build/mappings. The printed inventory does not prove each advertised primitive executes correctly.

**2. Curve aliases**

~~~text
"P-256" / "prime256v1" / "secp256r1"
  -> hintof_curve_name()
  -> assert returned NID == 415 for each alias
~~~

These are three explicit alias checks, not a full curve-name equivalence suite. The larger curve table is printed for inspection but is diagnostic.

**3. Cipher resource consistency**

~~~text
each registered cipher hint
  -> derive scheme from algorithm + mode
  -> compare with low 16 bits of registered scheme
  -> lookup hint again by fetch name
  -> derive scheme from looked-up algorithm + mode
  -> compare again with registered scheme
~~~

These assertions check internal metadata consistency. They do not perform encryption/decryption or validate known-answer ciphertext.


### Documentation and verification status

This document describes the Revision 1106 source tree. The testcase source was inspected, but it was **not rerun as part of this documentation update**. No execution result or environment-specific pass status is claimed here.

## 4. Relationships

- [`sdk/crypto/advisor/`](../../../../sdk/crypto/advisor/README.md) — implementation and lookup contract.
- [`test/testcase/crypto/`](../README.md) — shared crypto testcase area and supporting material.
- [`sdk/crypto/basic/`](../../../../sdk/crypto/basic/README.md) — crypto primitives and types that the metadata describes.

## 5. References

- [`testcase_advisor.cpp`](testcase_advisor.cpp) — source of the checks described above.
- [`sample.hpp`](../sample.hpp) — shared crypto testcase support.
