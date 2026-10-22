## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
```

# HTTP Testcases

## 1. What

`test/testcase/net/http/` covers HTTP URI parsing, request/response handling, authentication helpers, HTTP/2 frame serialization and parsing, and YAML-driven HTTP/2 frame consumption. These are source-level component tests and supplied capture-vector processing; they are not a live socket-level HTTP/2 interoperability suite.

| Source | Role |
|---|---|
| `testcase_http.cpp` | URI/query parsing, request/response fields, form-encoded body parameters, URL unescaping, Basic and Digest authentication |
| `testcase_http2_frame.cpp` | Known-answer HTTP/2 frame composition and parse/compose comparisons |
| `testvector_http2.cpp` | Feed YAML frame bytes through the network stream/protocol and HTTP/2 session path |
| `testvector_http2.yml` | Capture-derived frame sequences, descriptions and direction metadata |

## 2. How

### 2.1 URI and query parsing

1. Supply each URI or request target to `split_url` and check the fields explicitly asserted by the case, such as scheme, host, default port, full URI, path, query, and fragment.
2. For query-string cases, call `http_uri::to_keyvalue` to recover parameters such as `response_type`, `state`, `redirect_uri`, and `code`.
3. Compare the selected parsed fields and parameter values with their expected values.
4. Treat the verbose-only dump of split fields and decoded query pairs as diagnostics; only explicit assertions are checks.

### 2.2 Request and response handling

1. Open the supplied HTTP/1.1 request and inspect the parsed URI, method, and selected header fields.
2. Build a response and check its status code, content size, and content type.
3. Open the fixed 401 response and check its status, Content-Length, body size, Content-Type, and selected fields parsed from `WWW-Authenticate`.
4. For form-encoded-body cases, construct requests using query parameters and body parameters, serialize the requests, compare the resulting request streams, and check the recovered `client_id` values.
5. Run the URL-unescaping cases and compare the selected decoded URL values. These cases cover the supplied examples rather than every HTTP grammar branch.

### 2.3 Basic and Digest authentication

1. For Basic authentication, configure the credential resolver and use the dummy TCP socket/session setup; the test does not establish a real network exchange.
2. Construct the Authorization header and submit the correct password, then assert success.
3. Submit the incorrect password and assert failure.
4. For Digest cases, provide the selected algorithm and challenge/request parameters, then run the digest calculation or resolver path and check the explicit positive or negative outcome.
5. If the configured OpenSSL version is below the required minimum, the test records `not_supported`; that branch is not successful verification of the unsupported algorithm. Verbose intermediate calculations are diagnostic output.

### 2.4 HTTP/2 frame compose/read

1. Construct the first HTTP/2 frame and supply the expected serialized bytes as a hexadecimal vector.
2. Call `do_test_http2_frame(frame1, frame2, text, expect)` to serialize the constructed frame.
3. Compare the complete serialized byte sequence with the expected hex vector.
4. Read the expected bytes into the second frame, serialize that frame, and compare the first serialized buffer with the reserialized buffer.
5. Repeat for the provided SETTINGS, HEADERS, CONTINUATION, DATA, GOAWAY, and ALTSVC examples. HEADERS/CONTINUATION examples prepare their header payloads through HPACK.

### 2.5 HTTP/2 YAML schema and protocol consumption

The authoritative HTTP/2 YAML schema is defined here because this README documents the code that consumes it.

````yaml
testvector:
  - example: string                         # [mandatory] testcase
    schema: HTTP/2                          # [mandatory] "HTTP/2"
    items:
      - item: string                        # [mandatory] example label
        frame: hexstring                    # [mandatory] HTTP/2 frame/stream bytes
````

1. Read the `HTTP/2` vector entry and each `item`; the active callback consumes `item` and `frame`. Capture descriptions and direction metadata are not treated as expected decoded fields by this callback.
2. Decode `frame` from Base16 and append the resulting bytes to a `network_session` stream.
3. Pass available stream data through a `network_protocol_group` containing `http2_protocol`.
4. Pass each resulting buffer to `http2_session::consume` and record the returned status.
5. Release produced request and stream-buffer objects. This vector path does not compare expected request fields or a generated response byte sequence with YAML expectations.

## 3. Evidence

### 3.1 Source-level coverage

#### URI parsing and query values

```text
URI / request target
  -> split_url or http_request::open
  -> parse URI fields / query key-value pairs
  -> compare selected scheme, host, port, path, query and fragment
  -> compare selected query parameter values
```

**Assertion strength:** selected URI fields and values are explicitly compared. The verbose URL dump and query enumeration are diagnostics, not extra assertions.

#### Request/response parsing and composition

```text
fixed HTTP request or response text
  -> open / parse
  -> inspect method, URI, headers, status and body size
  -> compare selected expected fields
  -> assertions
```

Response composition separately checks status, content size and content type. The response parsing example checks 401 status, length, type and parsed Digest challenge parameters; it does not assert every possible HTTP header or grammar branch.

#### Form-encoded body handling

```text
request with query parameter
  -> serialize request A
request with form-encoded body parameter
  -> serialize request B
  -> compare request streams
  -> check recovered client_id values
```

**Assertion strength:** byte/string stream equality plus selected parsed parameter checks for the supplied cases.

#### Authentication paths

```text
Basic: configured credentials + Authorization header
  -> resolver
  -> correct password => success
  -> wrong password => failure

Digest: configured algorithm + challenge/request parameters
  -> digest calculation / resolver
  -> selected positive and negative status checks
  -> unsupported OpenSSL version => not_supported
```

**Assertion strength:** selected positive/negative outcomes are checked. The dummy session is not a live socket exchange; version-gated `not_supported` is not a pass for the unsupported algorithm.

#### HTTP/2 frame serialization and parse/compose

```text
constructed frame
  -> frame.write
  -> serialized bytes == expected hex
  -> frame.read(expected bytes)
  -> second frame.write
  -> first bytes == reserialized bytes
  -> assertions
```

**Assertion strength:** exact known-vector bytes and parse/compose byte equality for the listed frame examples.

#### HTTP/2 YAML vector consumption

```text
testvector_http2.yml
  -> schema "HTTP/2"
  -> item.frame -> Base16 decode
  -> network_session stream
  -> network_protocol_group(http2_protocol)
  -> http2_session::consume(buffer)
  -> record returned status
  -> release request/buffer objects
```

**Assertion strength:** records protocol/session consume status. It does not compare the capture's descriptive `comments` or `dir` fields with decoded output, and it does not assert expected request fields or response bytes.

### 3.2 Documentation and verification status

The latest available aggregate report for the parent `net` group is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole group. No separate HTTP-only count is available, and the report does not independently identify the tested source commit.

This documentation update did not execute tests.

## 4. Relationships

- [HPACK testcases](../hpack/README.md) — header encoding used by HTTP/2 HEADERS/CONTINUATION examples.
- [QPACK testcases](../qpack/README.md) — HTTP/3 header compression, a distinct codec/protocol layer.
- [Network testcase group](../README.md) — shared registration and aggregate report context.
- [Network SDK](../../../../sdk/net/README.md) — implementation area.

## 5. References

- `testcase_http.cpp`
- `testcase_http2_frame.cpp`
- `testvector_http2.cpp` and `testvector_http2.yml`
- RFC 7540 — HTTP/2.
- [Test Report Snapshot](../../test-report-status.md)
