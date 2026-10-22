# Authenticode Verification Applet

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1106                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

This directory contains a small executable applet for exercising the Authenticode verifier against a caller-supplied file. It is not a dedicated `test/testcase/crypto/authenticode/` unit-test directory.

## Source and build

- `sample.cpp` — command-line setup, verifier/context lifecycle, trust-certificate registration, and result reporting.
- `sample.hpp` — applet declarations and included module setup.
- `CMakeLists.txt` — builds the `authenticode` applet target through the repository's `maketest` helper.

## Execution model

The sample expects a target file path, opens an `authenticode_verifier` context, disables CRL downloading for the sample, registers `trust.crt` as trusted root material, invokes `verify()`, and closes the context. The target file and trust certificate must be available in the runtime environment. The source comments include Windows/MinGW and Linux path examples.

```text
target PE file + trust.crt
          ↓
 verifier context + trust configuration
          ↓
 authenticode_verifier::verify()
          ↓
 return code / testcase report
```

## Verification status

This is source-level documentation only. The applet was not executed during this documentation pass, and no applet-specific report was supplied as evidence. Do not infer a passing Authenticode test from aggregate crypto test totals.

## Relationships

- [`../../../sdk/crypto/authenticode/`](../../../sdk/crypto/authenticode/) — implementation being exercised.
- [`../../../sdk/crypto/authenticode/authenticode_verifier.md`](../../../sdk/crypto/authenticode/authenticode_verifier.md) — verification stages and trust/CRL caveats.
- `sample.cpp`, `sample.hpp`, `CMakeLists.txt` — source and build definition.
