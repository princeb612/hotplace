## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Documentation scope: QPACK testcase behavior and verification
```

# QPACK testcases

## 1. Role

This directory contains tests for QPACK, the header-compression format used by HTTP/3. The source covers RFC 9204 examples, dynamic-table capacity and eviction, encoder/decoder instruction streams, and header-block decoding. It tests QPACK encoding/decoding and state transitions; it is not itself a live HTTP/3 client/server test.

## 2. Test model

| Source | Main responsibility |
|---|---|
| `testcase_capacity.cpp` | Zero/tiny capacity, table state and eviction behavior |
| `testcase_qpack_stream.cpp` | Decode captured encoder instructions and HEADERS payload examples |
| `testcase_rfc9204.cpp` | RFC 9204 examples and encoded-byte expectations |
| `test.cpp` | Testcase registration/entry point |

The capacity tests create a `qpack_encoder` and `qpack_dynamic_table`, insert fields, then assert the expected encoded bytes and table capacity/entry/size state. Debug hooks count table-eviction events, making eviction behavior an explicit part of the assertion set.

The stream test includes captured examples of QPACK encoder-stream instructions and HEADERS payloads. These are byte-vector/parser examples; they should not be described as complete QUIC stream scheduling or HTTP/3 transaction tests.

## 3. Example: zero-capacity dynamic table

`test_zero_capacity()` leaves the dynamic table at capacity zero, inserts several fields, then checks an encoded field against a known hexadecimal expectation. It asserts that capacity, entry count and table size remain zero and that no eviction callback fired. This verifies the no-dynamic-table case directly.

The tiny-capacity tests extend the same idea to bounded table state and eviction. The RFC example tests use explicit expected byte sequences, so the encoding output—not merely a successful return code—is checked.

## 4. Test and verification status

### 4.1 Source-level coverage

The source includes capacity/eviction behavior, RFC 9204 examples and captured encoder/header stream examples. It does not by itself verify packet protection, QUIC loss recovery, HTTP/3 request semantics or live client/server interoperability.

### 4.2 Documentation and verification status

The latest available aggregate report for the parent `net` testcase group is recorded in [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole `net` group. The report does not separate QPACK from other network tests and does not independently identify the tested source commit.

This documentation update did not execute the test. Do not treat the aggregate network result as a QPACK-only count or as proof of end-to-end HTTP/3 behavior.

## 5. Relationships

- [HTTP/3 implementation](../../../../sdk/net/http/README.md) — HTTP/3 uses QPACK for header compression.
- [QUIC testcase material](../../quic/README.md) — packet/frame and capture-vector material; distinct from QPACK codec assertions.
- [HPACK testcases](../hpack/README.md) — HTTP/2 counterpart with a different compression synchronization model.
- [Parent network testcase report](../README.md) — aggregate runtime result.

## 6. References

- RFC 9204 — QPACK: Field Compression for HTTP/3.
- `testcase_capacity.cpp`
- `testcase_qpack_stream.cpp`
- `testcase_rfc9204.cpp`
- [Test Report Snapshot](../../test-report-status.md)

## 7. Developer Notes

Keep QPACK codec tests, QUIC packet parsing, and HTTP/3 end-to-end behavior as separate verification claims. Report counts should remain tied to the granularity the report actually provides; the current known report has a parent `net` row, not separate HPACK or QPACK rows.
