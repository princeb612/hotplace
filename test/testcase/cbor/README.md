## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# CBOR testcase assets

## 1. Role

Identifies CBOR test vectors and documents the YAML vector schema used by the test sources.

## 2. Test model

The directory contains RFC 7049/RFC 8949 examples and a YAML schema for encoded CBOR and diagnostic expressions.

### Existing vector schema and notes

### CBOR

* test vector
  * RFC 7049 Concise Binary Object Representation (CBOR)
    * Appendix A.  Examples
    * Appendix B.  Jump Table
  * RFC 8949 Concise Binary Object Representation (CBOR)
    * Appendix A.  Examples of Encoded CBOR Data Items
    * Appendix B.  Jump Table for Initial Byte

### YAML schema

* CBOR YAML schema

````
testvector:
  - example: string          # [mandatory] testcase
    schema: RFC 7049         # [mandatory] "RFC 7049"
    items:
      - item: string         # [mandatory] diagnostic, description
        cbor: hexstring      # [mandatory]
        # [mandatory] diagnostic expression
        diag: |
          string
        loss: boolean        # dataloss encoding e.g. float(5.960464477539063e-8) FP32 5.96046448e-08 BINARY32 33800000
````

## 3. Example: RFC CBOR vectors

A YAML vector associates an example name and schema with encoded hex, diagnostic text, and optional lossy-number details.

## 4. Test and verification status

### 4.1 Source-level coverage

`testcase_rfc7049.cpp` compares expected bytes and diagnostic/concise text. `testvector_cbor.cpp` checks YAML-based cases using explicit test assertions.

### 4.2 Documentation and verification status

The supplied report is identified as **MinGW64, source revision 1104**: **251 pass, 0 expt, 0 fail, 0 skip, 0 triv**. The documentation task did not rerun the tests.

## 5. Relationships

- `sdk/io/cbor/` contains the implementation.
- `testcase_rfc7049.cpp` and `testvector_cbor.cpp` consume the vectors.

## 6. References

- RFC 7049, Appendix A and B.
- RFC 8949, Appendix A and B.
- `testcase_rfc7049.cpp`, `testvector_cbor.cpp`, `testvector_cbor.yml` (Revision 1104).
