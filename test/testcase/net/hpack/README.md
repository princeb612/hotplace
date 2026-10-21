## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Documentation scope: HPACK testcase behavior and verification
```

# HPACK testcases

## 1. Role

This directory contains tests for HPACK, the header-compression format used by HTTP/2. The source covers RFC 7541 integer and header representations, Huffman coding, dynamic-table behavior, and YAML-driven header blocks. The suite tests the compression layer; it is not by itself a complete HTTP/2 client/server interoperability test.

## 2. Test model

| Source | Main responsibility |
|---|---|
| `testcase_huffman.cpp` | RFC 7541 Appendix B Huffman encode/decode examples |
| `testcase_rfc7541.cpp` | RFC integer/header representations and encoder/decoder behavior |
| `testvector_hpack.cpp` | Read YAML vectors, decode header blocks, and compare decoded key/value pairs |
| `testvector_hpack.yml` | Named examples and expected header maps |
| `test.cpp` | Testcase registration/entry point |

The RFC examples compare encoded bytes against expected hexadecimal values and exercise decode paths. The YAML-driven path uses an HPACK dynamic table, decodes the header block into a multimap, commits table state as required by the loop, and compares the decoded map with the vector's expected key/value entries.

## 3. Example: Huffman known-answer round trip

In `testcase_huffman.cpp`, `do_test_huffman_codes_routine(sample, expect)` encodes a sample string, compares the output bytes to the RFC-provided hexadecimal vector, then decodes those bytes and checks both successful return status and equality with the original input bytes. Examples include `www.example.com` and `no-cache`. This tests a known-answer encoding and a round trip; it does not alone establish malformed-input robustness or full HTTP/2 behavior.

A second useful path is `testvector_hpack.cpp`: each YAML item's `hpack` field is decoded from Base16, parsed as HPACK header representations, and compared with the expected `keyvalue` map. The dynamic table is carried through the sequence where the vector requires state.

## 4. Test and verification status

### 4.1 Source-level coverage

The source includes Huffman vectors, RFC 7541 examples and YAML-driven header decoding. The dynamic-table state is part of the behavior under test; an isolated header block may not represent the same result as a sequence of blocks sharing a table.

### 4.2 Documentation and verification status

The latest available aggregate report for the parent `net` testcase group is recorded in [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole `net` group. The report does not separate HPACK results from other network tests and does not independently identify the tested source commit.

This documentation update did not execute the test. Do not treat the aggregate result as an HPACK-only count or as proof of HTTP/2 end-to-end interoperability.

## 5. Relationships

- [HTTP/2 implementation](../../../../sdk/net/http/README.md) — consumes HPACK for HTTP/2 header compression.
- [Base Huffman/encoding facilities](../../../../sdk/base/README.md) — shared low-level encoding support where used by the implementation.
- [QPACK testcases](../qpack/README.md) — related header compression for HTTP/3, with different dynamic-table synchronization rules.
- [Parent network testcase report](../README.md) — aggregate runtime result.

## 6. References

- RFC 7541 — HPACK: Header Compression for HTTP/2.
- `testcase_huffman.cpp`
- `testcase_rfc7541.cpp`
- `testvector_hpack.cpp` and `testvector_hpack.yml`
- [Test Report Snapshot](../../test-report-status.md)

## 7. Developer Notes

Preserve the distinction between HPACK codec/vector tests and full HTTP/2 integration. When documenting a new report, record the source revision and environment and do not assign the parent `net` totals to this directory unless the report provides a separate HPACK row.
