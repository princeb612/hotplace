## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
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

## 3. Example: testcase entry points

The concrete test entry points and test-vector schema are retained below. Source-level assertions, rather than the existence of a source file, determine what is actually checked.

Source files:
- `sample.cpp`

## 4. Test and verification status

### 4.1 Source-level coverage

Coverage must be inferred from the actual testcase functions and assertions. The directory README and the presence of test sources do not prove that every protocol path is meaningfully checked.

### 4.2 Documentation and verification status

This README documents the directory and source inventory. It does not itself prove a successful runtime execution. The available report archive does not identify the exact OS, compiler configuration, or source revision for its results.

## 5. Relationships

- Corresponding implementation documentation is under `sdk/net/`.
- HTTP compression testcases are maintained in the sibling `hpack/` and `qpack/` directories.
- Shared test registration is defined by the surrounding testcase CMake configuration.

## 6. References

- `test/testcase/net/sample.cpp`
