## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# QPACK Testcases

## 1. Role

Documents QPACK source-level checks for RFC 9204 examples, dynamic-table capacity/eviction behavior, and encoder/decoder streams.

## 2. Test model

`testcase_capacity.cpp` checks capacities, table entry counts, eviction counts, table sizes, and expected encoded bytes. `testcase_rfc9204.cpp` checks selected RFC examples, decoded field values, table capacity/size, and decoder acknowledgements. `testcase_qpack_stream.cpp` records results for QPACK stream cases.

## 3. Example: Dynamic-table capacity and RFC 9204 field sections

The capacity tests assert zero-capacity and bounded-capacity behavior, including table entries and evictions. RFC example tests compare encoded bytes and verify decoded `:authority` and `:path` fields and table state.

## 4. Test and verification status

### 4.1 Source-level coverage

The inspected sources contain concrete byte comparisons and dynamic-table state assertions. Stream tests report each case result; this documentation does not claim complete HTTP/3 or QUIC transport conformance.

### 4.2 Documentation and verification status

The supplied `net/report` records 268 pass and 1 expt, with no fail/skip/triv entries. The report does not identify OS/compiler configuration or source revision, and this documentation pass did not execute tests; therefore it cannot prove these sources ran against Revision 1104.

## 5. Relationships

- Implementation: `sdk/net/http/qpack/`
- HTTP/3 and QUIC integration documentation: `sdk/net/http/http-protocol-stack.md` and `sdk/net/tls/`
- RFC: RFC 9204.

## 6. References

- `test/testcase/net/qpack/testcase_capacity.cpp`
- `test/testcase/net/qpack/testcase_rfc9204.cpp`
- `test/testcase/net/qpack/testcase_qpack_stream.cpp`
