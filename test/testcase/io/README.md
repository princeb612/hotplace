## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ Documentation scope: testcase inventory and  │
│ verification boundaries                      │
└──────────────────────────────────────────────┘
```

# I/O testcase suite

## 1. Role

This directory contains testcase entry points for I/O representation, parser, file-stream, string/URL, and selected OS-integration facilities. It is a mixed suite: the main entry point runs several groups, while MLFQ and netlink tests are enabled only by explicit command-line options.

## 2. Test model

`sample.cpp` registers the testcase harness/logger, parses options, and then runs these groups:

| Testcase call | Area | Source |
|---|---|---|
| `testcase_oid()` | OID dictionary and conversion | `basic/testcase_oid.cpp` |
| `testcase_payload()`, `testcase_payload_quic()` | Binary field layouts and payload cases | `basic/testcase_payload.cpp` |
| `testcase_filestream()` | File-backed stream and memory mapping | `stream/testcase_filestream.cpp` |
| `testcase_string()` | Tokenization and URL/text handling | `string/testcase_string.cpp` |
| `testcase_lexer()`, `testcase_parser()`, `testcase_testvector_parser()` | Lexical analysis, parser behavior and vector parsing | `parser/` |
| `testcase_mlfq()` | Multi-level feedback queue | `system/testcase_mlfq.cpp`, only with `-mlfq` |
| `testcase_netlink()` | Linux process-event/netlink path | `system/testcase_netlink.cpp`, only with `-netlink` |

The CMake target collects source files from `basic/`, `parser/`, `stream/`, `string/`, and `system/`, and copies YAML/vector data into the build tree.

## 3. Example: payload read/write round trip

In `basic/testcase_payload.cpp`, the testcase declares a field sequence, writes it to bytes, toggles a named group to omit optional fields, and compares the full output with expected bytes. For the read path it registers a length reference, reads a known byte sequence, checks the decoded fields, then serializes the result again and compares it with the original input. This checks both the field layout and a round-trip property at source level.

## 4. Test and verification status

### 4.1 Source-level coverage

The default entry point does not invoke every optional path: MLFQ and netlink require `-mlfq` and `-netlink`. Netlink coverage is Linux/glibc-dependent. The existence of these functions does not prove that the optional cases ran.

### 4.2 Documentation and verification status

The latest available aggregate report is recorded in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv entries for the `io` group. The report payload does not independently identify the tested source commit, exact GCC version, or full build configuration.

The optional `-mlfq` and `-netlink` paths must not be assumed to have run just because the aggregate report has no categorized failures. Keep the last known report visible until a newer, revision-associated snapshot is supplied. This documentation update did not execute the test.

This document records the current source-level dispatch and assertion examples. It does not claim runtime execution in a specific environment. Use the environment matrix in [testcase README](../README.md) to interpret CTest and additional diagnostic reports.

## 5. Relationships

- `sdk/io/README.md` — I/O subsystem responsibilities.
- `sdk/io/basic/`, `sdk/io/parser/`, `sdk/io/stream/`, `sdk/io/string/`, `sdk/io/system/` — implementation areas.
- `test/testcase/io/CMakeLists.txt` — target source and test-vector registration.

## 6. References

- `test/testcase/io/sample.cpp`
- `test/testcase/io/CMakeLists.txt`
- `test/testcase/io/basic/testcase_payload.cpp`
- `test/testcase/io/basic/testcase_oid.cpp`
- `test/testcase/io/stream/testcase_filestream.cpp`
