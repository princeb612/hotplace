## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```
# Basic I/O Testcases

## 1. Role

Documents the source-level tests for `sdk/io/basic`, primarily the declarative `payload` read/write layer and its QUIC-specific encoded-field extension.

## 2. Test model

1. `testcase_payload.cpp` exercises field-order serialization/deserialization, reference-sized binary fields, optional groups, condition-controlled groups, 24-bit/48-bit values, and bignumber values. `testcase_payload_quic.cpp` covers QUIC integer/payload integration.

## 3. Example: payload write/read round trip

1. For a detailed source walkthrough, see [Basic I/O testcase README](README.md): it follows the field layout through group-enabled and group-disabled serialization, uses `set_reference_value` to infer a variable field length while reading, and describes the QUIC varint known-answer/round-trip cases. This file remains the concise testcase index; the README carries the full flow so the explanation is not duplicated here.

## 4. Test and verification status

### 4.1 Source-level coverage

Assertions compare expected payload values and byte buffers in several paths. The source includes checks for both serialization bytes and values recovered during decoding; individual cases should still be reviewed for boundary coverage before claiming exhaustive validation.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. There is no separate `io/basic` row, so the parent count must not be attributed to these cases alone. The report does not independently identify the tested source commit or exact build configuration. This documentation update did not rerun tests.

## 5. Relationships

- Implementation: `sdk/io/`
- Test registration: the adjacent `CMakeLists.txt` and shared testcase harness.

## 6. References

- `test/testcase/io/basic/testcase_payload.cpp`
- `test/testcase/io/basic/testcase_payload_quic.cpp`
