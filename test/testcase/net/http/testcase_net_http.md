## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HTTP Testcases

## 1. Role

Documents source-level checks for HTTP URI parsing, request/response fields, and HTTP/2 frame serialization and parsing.

## 2. Test model

`testcase_http.cpp` contains URI, request, response composition, and response parsing tests. `testcase_http2_frame.cpp` uses `do_test_http2_frame(...)` to compose a frame, compare bytes with an expected vector, parse it again, and compare the reconstructed binary.

## 3. Example: HTTP/2 frame compose/read round trip

`do_test_http2_frame(...)` compares the composed frame bytes with the expected RFC-style hex vector and then compares the reserialized result after reading the frame. The file applies this pattern to SETTINGS, HEADERS, CONTINUATION, DATA, GOAWAY, and ALTSVC frames.

## 4. Test and verification status

### 4.1 Source-level coverage

URI assertions explicitly check scheme, host, port, path, query, and fragment; request/response tests check selected method, header, status, content length, and content type. Frame tests compare selected encoded vectors and read-back bytes. These are meaningful checks for the listed paths, not exhaustive HTTP conformance proof.

### 4.2 Documentation and verification status

The supplied `net/report` records 268 pass and 1 expt, with no fail/skip/triv entries. The report does not identify OS/compiler configuration or source revision, and this documentation pass did not execute tests; therefore it cannot prove these sources ran against Revision 1104.

## 5. Relationships

- Implementation: `sdk/net/http/`
- Frame protocol documentation: `sdk/net/http/http-protocol-stack.md`
- HPACK/QPACK tests: sibling `hpack/` and `qpack/` directories.

## 6. References

- `test/testcase/net/http/testcase_http.cpp`
- `test/testcase/net/http/testcase_http2_frame.cpp`
- `test/testcase/net/http/testvector_http2.cpp`
- `test/testcase/net/http/testvector_http2.yml`
