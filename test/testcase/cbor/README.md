## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase assets and verification           │
└──────────────────────────────────────────────┘
```

# CBOR testcase assets

## 1. Role

This directory preserves CBOR test vectors and the YAML schema consumed by the CBOR testcase sources. The assets make encoded bytes and their diagnostic/concise representations reviewable together; they are test inputs and expected results, not the implementation itself.

## 2. Test model

The directory contains RFC 7049/RFC 8949 examples and a YAML schema for encoded CBOR and diagnostic expressions.

### Existing vector schema and notes

### CBOR

- RFC 7049, Concise Binary Object Representation (CBOR)
  - Appendix A: Examples
  - Appendix B: Jump Table
- RFC 8949, Concise Binary Object Representation (CBOR)
  - Appendix A: Examples of Encoded CBOR Data Items
  - Appendix B: Jump Table for Initial Byte

### YAML schema

```yaml
testvector:
  - example: string
    schema: RFC 7049
    items:
      - item: string
        cbor: hexstring
        diag: |
          string
        loss: boolean
```

The `loss` field records cases where a floating-point representation is lossy, with explanatory details in the original vector file.

## 3. Example: RFC CBOR vectors

A vector item associates an example name and schema with encoded hex, a diagnostic expression, and optional lossy-number details. `testcase_rfc7049.cpp` compares the expected bytes and diagnostic/concise text; `testvector_cbor.cpp` reads the YAML cases and checks their results through explicit assertions. This links the RFC asset to the concrete testcase rather than treating the schema as documentation only.

## 4. Test and verification status

### 4.1 Source-level coverage

The source checks RFC example vectors and YAML-driven cases. These tests provide known-answer evidence for the listed data items, but do not by themselves establish complete CBOR conformance, exhaustive malformed-input handling, or all RFC 8949 edge cases.

### 4.2 Documentation and verification status

The latest available aggregate report is indexed in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 251 pass, 0 expt, 0 fail, 0 skip and 0 triv entries for the `cbor` group. The report payload does not independently identify the tested source commit or exact build configuration. The documentation basis is Revision 1105, distinct from the last known test-run context. This documentation update did not rerun the tests.

## 5. Relationships

- `sdk/io/cbor/` contains the CBOR implementation.
- `testcase_rfc7049.cpp` and `testvector_cbor.cpp` consume the vectors.
- [Test Report Snapshot](../test-report-status.md) records the last known aggregate execution result and its provenance limits.

## 6. References

- RFC 7049, Appendix A and B.
- RFC 8949, Appendix A and B.
- `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, `testvector_cbor.yml` (Revision 1104).
