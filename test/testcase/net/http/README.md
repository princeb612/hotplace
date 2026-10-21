## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```

# HTTP testcases

## 1. Role

This directory contains HTTP request/response and HTTP/2 frame testcase sources, along with YAML-driven test-vector support. The suite has two distinct layers: object-level HTTP/2 frame compose/read checks, and YAML-driven frame input passed through the network stream/protocol and HTTP/2 session path. The YAML test uses capture-derived frame vectors; it is not a live client/server exchange.

## 2. Test model

- `testcase_http.cpp` — HTTP request/response-oriented cases.
- `testcase_http2_frame.cpp` — known-answer frame serialization and parse/compose round trips.
- `testvector_http2.cpp` — YAML vector-driven frame consumption through `network_protocol_group` and `http2_session`.
- `testvector_http2.yml` — named examples and expected frame data.

## 3. Example: HTTP/2 frame assertions and protocol consumption

### Frame composition and parse/compose round trip

`testcase_http2_frame.cpp` uses `do_test_http2_frame` for each example. It serializes a constructed frame and compares its complete bytes with a fixed expected hexadecimal vector. It then parses the expected bytes into a second frame object, serializes that object again, and compares the two serialized buffers. The examples include SETTINGS, HEADERS, CONTINUATION, DATA, GOAWAY and ALTSVC frames. HEADERS and CONTINUATION payloads are prepared with an HPACK stream and shared dynamic table, so the vectors also exercise the frame boundary around compressed headers.

### Capture-vector processing through the protocol layer

`testvector_http2.cpp` reads the `frame` field from `testvector_http2.yml`, converts the hex to bytes, appends them to the session stream, and consumes queued stream data through a `network_protocol_group` containing `http2_protocol`. The resulting content is passed to `http2_session::consume`; the test harness records the returned status and releases any produced request and stream-buffer objects. This is a protocol-consumption path over supplied vectors, not a full socket-level interoperability test.

## 4. Test and verification status

### 4.1 Source-level coverage

The sources cover HTTP request-related cases, known-answer HTTP/2 frame serialization and parse/compose round trips, and YAML-driven frame consumption. The listed frame examples do not imply coverage of every HTTP/2 frame type, malformed-frame condition, flow-control transition, or end-to-end request/response exchange.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the entire `net` group. No separate HTTP testcase row is available, so the parent counts must not be presented as HTTP-only results. The report does not independently identify the tested source commit or exact build configuration. This documentation update did not execute the test.

## 5. Relationships

- Corresponding implementation documentation is under `sdk/net/`.
- [HPACK testcases](../hpack/README.md) and [QPACK testcases](../qpack/README.md) cover header compression at different protocol layers.
- [Parent network testcase report](../README.md) — aggregate `net` result and scope limits.
- Shared test registration is defined by the surrounding testcase CMake configuration.

## 6. References

- `test/testcase/net/http/testcase_http.cpp`
- `test/testcase/net/http/testcase_http2_frame.cpp`
- `test/testcase/net/http/testvector_http2.cpp`
- `test/testcase/net/http/testvector_http2.yml`
