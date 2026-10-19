## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HPACK Testcases

## 1. Role

Documents HPACK checks for RFC 7541 integer representation, header field representation, Huffman coding, and YAML-backed header vectors.

## 2. Test model

`testcase_huffman.cpp` checks encoded Huffman bytes and decoded sample bytes. `testcase_rfc7541.cpp` contains RFC 7541 examples with explicit expected byte sequences and dynamic-table state assertions. `testvector_hpack.cpp` checks decoded key/value fields from YAML test vectors.

## 3. Example: RFC 7541 integer and header examples

`test_rfc7541_c_1()` checks fixed integer encodings such as 10, 1337, and 42. Header-field examples compare encoded bytes and selected dynamic-table state; Huffman helpers compare encoded and decoded binary values against expected samples.

## 4. Test and verification status

### 4.1 Source-level coverage

The source contains explicit byte-vector assertions and selected decode/table-state checks. Test vectors provide additional inputs, but their presence alone does not mean every vector was consumed or passed in the report.

### 4.2 Documentation and verification status

The supplied `net/report` records 268 pass and 1 expt, with no fail/skip/triv entries. The report does not identify OS/compiler configuration or source revision, and this documentation pass did not execute tests; therefore it cannot prove these sources ran against Revision 1104.

## 5. Relationships

- Implementation: `sdk/net/http/hpack/`
- HTTP/2 frame tests: `test/testcase/net/http/`
- RFC: RFC 7541.

## 6. References

- `test/testcase/net/hpack/testcase_rfc7541.cpp`
- `test/testcase/net/hpack/testcase_huffman.cpp`
- `test/testcase/net/hpack/testvector_hpack.cpp`
- `test/testcase/net/hpack/testvector_hpack.yml`
