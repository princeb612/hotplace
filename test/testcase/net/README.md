## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase inputs, procedures & verification │
└──────────────────────────────────────────────┘
```

# Network Testcases

## 1. What

`test/testcase/net/` is the network testcase group. Its entry point, `sample.cpp`, registers separate tests for IP address ACLs, HPACK/Huffman and RFC 7541 behavior, HTTP/HTTP/2 parsing and frame handling, and QPACK/RFC 9204 behavior. The directory is not one end-to-end network interoperability test: each child test exercises a narrower API or vector path.

The YAML-backed paths use two distinct models:

- **HPACK:** a compressed header block is input; the decoded header name/value multimap is compared with the vector's expected `keyvalue` map. A shared dynamic table carries state across items.
- **HTTP/2:** a serialized frame byte sequence is input to a stream/protocol/session consumption path; the testcase checks the returned processing status. This path does not compare a generated response frame or decoded request fields against a YAML expected-value map.

The group also includes tests that do not use these YAML schemas, such as the explicit RFC 7541 known-answer examples, HTTP/2 frame compose/read checks, ACL decisions, and QPACK examples.

## 2. How

### 2.1 Test dispatch and build inputs

1. The network testcase entry point in `sample.cpp` creates the shared command-line and testcase harness.
2. It dispatches the network testcase functions: `testcase_acl()`; `testcase_huffman()` and `testcase_rfc7541()`; `testcase_testvector_hpack()`; `testcase_http()`, `testcase_http2_frame()`, and `testcase_testvector_http2()`; and `testcase_capacity()`, `testcase_qpack_stream()`, and `testcase_rfc9204()`.
3. The network testcase CMake configuration collects sources from `basic/`, `hpack/`, `http/`, and `qpack/`, copies YAML data into the test build directory, and registers the `net` test target.
4. YAML-driven tests depend on the relevant vector files being available in the build's testcase data location. Their actual data interpretation and assertions are described in the owning subdirectory README.

### 2.2 YAML vector formats

The group has two YAML vector formats. Their full schema examples and test-specific consumption procedures are maintained in the README for the code that consumes them, avoiding duplicate schema definitions here.

- **HPACK:** `testvector_hpack.cpp` consumes `item`, Base16-encoded `hpack`, and expected `keyvalue` fields. See [HPACK testcases](hpack/README.md) for the authoritative schema and numbered decode procedure. The expected decoded multimap is compared with the actual decoded header map. The dynamic table is shared across the item loop, so vector order and state transitions matter.
- **HTTP/2:** `testvector_http2.cpp` consumes `item` and Base16-encoded `frame` bytes. See [HTTP testcases](http/README.md) for the authoritative schema and numbered protocol-consumption procedure. The callback records the HTTP/2 session consume status; it does not compare expected request fields or response bytes from the YAML.

### 2.3 Other testcase procedures

The remaining tests use inputs constructed directly in C++ rather than these two YAML schemas.

- **HPACK Huffman:** each RFC sample is encoded and compared with fixed hexadecimal bytes; the result is decoded and checked for success and equality with the original sample.
- **RFC 7541:** integer and header representations are checked against selected fixed encodings, decoded values, and dynamic-table state. The exact assertions vary by example.
- **HTTP/2 frame compose/read:** constructed frames are serialized and compared with expected hexadecimal vectors; the expected bytes are parsed into a second frame and reserialized for a byte-equality check. Examples include SETTINGS, HEADERS, CONTINUATION, DATA, GOAWAY, and ALTSVC.
- **ACL:** address, CIDR, and range rules are evaluated in whitelist and blacklist modes against expected booleans. IPv6 execution depends on `SUPPORT_IPV6`.
- **QPACK:** RFC 9204 examples and capacity/stream tests check selected encoded bytes, decoded fields, dynamic-table state, eviction events, and stream-processing status. These are codec-layer checks, not a live QUIC/HTTP/3 transaction.

## 3. Evidence

### 3.1 Source-level coverage

The diagrams below trace the principal source verification paths. They intentionally distinguish exact data comparisons from status-only checks and from diagnostic output.

#### HPACK YAML vector — decoded header-map equality

```text
testvector_hpack.yml
  -> yaml_testcase dispatch: schema "HPACK"
  -> item.hpack
  -> Base16 decode
  -> item.keyvalue -> expected multimap
  -> shared hpack_dynamic_table
  -> hpack_encoder::decode_header (repeat until block consumed)
  -> commit dynamic-table state after each header
  -> actual decoded multimap == expected multimap
  -> _test_case.assert
```

**Assertion strength:** exact equality of the decoded header name/value multimap. Dynamic-table state is carried across vector items and dumped for diagnostics, but the YAML callback does not independently compare a complete expected dynamic-table snapshot.

#### HTTP/2 YAML vector — protocol-consumption status

```text
testvector_http2.yml
  -> yaml_testcase dispatch: schema "HTTP/2"
  -> item.frame
  -> Base16 decode
  -> network_session stream.produce
  -> network_session.consume(protocol_group: http2_protocol)
  -> each network_stream_data buffer
  -> http2_session::consume
  -> _test_case.test(return status)
  -> release produced request/buffer objects
```

**Assertion strength:** records the return status from `http2_session::consume`. The YAML path does not compare a generated response against an expected byte vector, does not assert expected decoded request fields, and does not use the YAML `dir` field as a direction-specific assertion.

#### HPACK Huffman known-answer and round-trip path

```text
RFC sample string + expected hex
  -> Huffman encode
  -> encoded bytes == expected bytes
  -> Huffman decode
  -> decode status == success
  -> decoded bytes == original sample bytes
  -> assertions
```

**Assertion strength:** both a fixed expected encoding and successful decode with exact original-byte equality are checked.

#### RFC 7541 integer/header representation path

```text
integer/header input + RFC expected hex
  -> encode integer or header
  -> encoded bytes == expected hex
  -> decode representation/header
  -> decoded integer or name/value == expected input
  -> selected dynamic-table entry count/size assertions
  -> where exercised, encoder table == decoder table
```

**Assertion strength:** exact known-answer byte comparisons and selected decoded-value/table-state assertions. The assertion set varies by RFC example; do not assume every example checks every state property.

#### HTTP/2 frame compose/read path

```text
constructed frame object
  -> frame.write
  -> serialized bytes == expected hex
  -> frame.read(expected bytes)
  -> second frame.write
  -> first serialized bytes == second serialized bytes
  -> assertions
```

**Assertion strength:** full serialized-byte equality against a known vector plus byte equality after parse/compose. This applies to the explicit frame examples in `testcase_http2_frame.cpp`, not every possible frame type or malformed input.

#### ACL decision path

```text
address/CIDR/range rules
  -> choose whitelist or blacklist mode
  -> ipaddr_acl::determine(address)
  -> returned decision == expected boolean
  -> testcase result
```

**Assertion strength:** explicit decision checks for the source's selected addresses and rule combinations. This is not OS firewall enforcement. IPv6 assertions are conditional on `SUPPORT_IPV6`.

#### QPACK capacity and RFC vector paths

```text
capacity / RFC 9204 test input
  -> qpack encoder, dynamic table, or stream decoder
  -> encoded bytes and/or decoded fields
  -> selected table capacity/size/entry and eviction checks
  -> testcase assertions
```

**Assertion strength:** QPACK sources include concrete encoded-byte and state assertions in the capacity/RFC paths; stream cases should be described according to their individual checks. These tests do not establish full QUIC transport or HTTP/3 interoperability.

### 3.2 Documentation and verification status

The latest available aggregate report is indexed in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv entries for the entire `net` group. The report does not independently identify the tested source commit or exact build configuration, and it does not provide separate HPACK, HTTP, ACL or QPACK totals. Do not attribute the parent-group count to an individual path.

This documentation update did not execute tests. The source-level diagrams describe inspected assertions, not a new runtime result.

## 4. Relationships

- `test/testcase/net/sample.cpp` — shared entry point and testcase dispatch.
- `test/testcase/net/hpack/testvector_hpack.cpp` and `testvector_hpack.yml` — HPACK YAML consumer and vectors.
- `test/testcase/net/hpack/testcase_huffman.cpp` — Huffman known-answer and round-trip checks.
- `test/testcase/net/hpack/testcase_rfc7541.cpp` — RFC 7541 integer/header and dynamic-table assertions.
- `test/testcase/net/http/testvector_http2.cpp` and `testvector_http2.yml` — HTTP/2 YAML protocol-consumption path.
- `test/testcase/net/http/testcase_http2_frame.cpp` — frame compose/read byte comparisons.
- `test/testcase/net/qpack/` — RFC 9204, capacity, and stream test sources.
- [Test Report Snapshot](../test-report-status.md) — aggregate runtime report and provenance limits.

## 5. References
