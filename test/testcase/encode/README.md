## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                         │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

### Encoding testcases

This directory contains the tests/samples for the corresponding hotplace module.

See [testcase_encoding.md](testcase_encoding.md) for the source-level coverage review and the supplied report summary.

#### test sources

* `sample.cpp`
* `testcase_base128.cpp`
* `testcase_base16.cpp`
* `testcase_base64.cpp`
* `testcase_huffman.cpp`

#### test data / build files

* `CMakeLists.txt`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.
