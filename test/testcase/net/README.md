## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Network Testcases

## 1. Role

This directory contains network testcase support material and test-vector schemas. Concrete coverage is defined by the child testcase sources and their assertions.

## 2. Test model

Test source files in this directory: `sample.cpp`

#### HPACK

* test vector
  * RFC 7541 HPACK: Header Compression for HTTP/2
  * QPACK: Field Compression for HTTP/3

#### YAML schema

* HPACK schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: HPACK                           # [mandatory] "HPACK"
    items:
      - item: string                        # [mandatory]
        hpack: hexstring                    # [mandatory]
        keyvalue:                           #
          key: value                        #
````

* HTTP/2 schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: HTTP/2                          # [mandatory] "HTTP/2"
    items:
      - item: string                        # [mandatory]
        frame: hexstring                    # [mandatory] HTTP/2 frame
````

## 3. Example: testcase dispatch and vector paths

`sample.cpp` initializes the shared testcase harness and then calls `testcase_acl()`, HPACK Huffman/RFC 7541 tests, HTTP tests, HTTP/2 frame tests, QPACK RFC 9204/capacity/stream tests, and other registered network checks. These are separate testcase functions; the single entry point does not mean all HTTP/2, HPACK and QPACK behavior is checked by one end-to-end scenario.

- `test/testcase/net/basic/testcase_acl.cpp` — IP address ACL rules and whitelist/blacklist decisions.
- `test/testcase/net/http/testcase_http2_frame.cpp` — HTTP/2 frame-level behavior.
- `test/testcase/net/http/testvector_http2.cpp` — HTTP/2 test-vector path.
- `test/testcase/net/hpack/` — HPACK/Huffman and RFC vectors.
- `test/testcase/net/qpack/` — QPACK RFC/capacity/stream tests.

The HPACK and HTTP/2 YAML schemas retained in this README describe the vector inputs; the C++ consumer and assertions determine the actual checks.

## 4. Test and verification status

### 4.1 Source-level coverage

Coverage must be inferred from the actual testcase functions and assertions. The directory README and the presence of test sources do not prove that every protocol path is meaningfully checked.

### 4.2 Documentation and verification status

The latest available aggregate report is indexed in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv entries for the entire `net` group. The report files do not independently identify the tested source commit or exact build configuration. The parent totals must not be copied as per-directory results for HTTP, HPACK or QPACK. This documentation update did not execute the test.

## 5. Relationships

- Corresponding implementation documentation is under `sdk/net/`.
- HTTP compression testcases are maintained in the sibling `hpack/` and `qpack/` directories.
- Shared test registration is defined by the surrounding testcase CMake configuration.

## 6. References

- `test/testcase/net/sample.cpp`

## Latest recorded runtime report

The latest shared report snapshot is indexed in [Test Report Snapshot](../test-report-status.md). It records 268 pass, 1 expt, 0 fail, 0 skip and 0 triv entries for the `net` group. The associated run context supplied in the conversation is Revision 1104 on MinGW64/GCC with CTest; the report payload does not independently identify the tested source commit or exact build configuration. Preserve this result until a newer report set is available; do not infer a fresh run from the current documentation revision.
