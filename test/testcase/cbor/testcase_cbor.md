## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# CBOR testcase analysis

## 1. Role

Records the source-level checks for CBOR encoding, diagnostic expressions, parsing, and YAML vectors.

## 2. Test model

```text
RFC examples / YAML vectors
          │
          ▼
 cbor_reader / object model / encoder
          │
          ▼
 expected bytes and diagnostic form
          │
          ▼
 test_case result
```

The main sources are `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, and `sample.cpp`; vector definitions live in `testvector_cbor.yml`.

## 3. Example: RFC 7049 and YAML vectors

`testcase_rfc7049.cpp` compares encoded bytes with expected hexadecimal values and compares concise/diagnostic representations. The named `test_rfc7049_table4_1()` and `test_rfc7049_table4_2()` functions cover the RFC’s scalar and collection examples. `testvector_cbor.cpp` checks the YAML-based vector cases through explicit `_test_case.assert(...)` calls.

## 4. Test and verification status

### 4.1 Source-level coverage

- RFC example encoding compares actual output with expected byte strings.
- Diagnostic/concise output paths compare generated text with expected values.
- YAML vector cases are evaluated by the vector test source.
- The sample application is a separate sample path and should not be counted as an independent assertion suite merely because it builds.

### 4.2 Documentation and verification status

The supplied report is identified as **MinGW64, source revision 1104**: **251 pass, 0 expt, 0 fail, 0 skip, 0 triv**. This report is execution evidence for that environment/revision as specified by the user. The documentation task did not rerun the test suite.

## 5. Relationships

- `sdk/io/cbor/` — reader, object model, encoder, and visitors.
- `test/testcase/cbor/testvector_cbor.yml` — data-driven vector inputs.
- `sdk/crypto/cose/` and its tests consume CBOR structures.

## 6. References

- RFC 7049, Appendix A and B.
- RFC 8949, Appendix A and B.
- `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, `testvector_cbor.yml` (Revision 1104).
