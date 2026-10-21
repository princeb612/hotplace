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

# Basic Testcases

## 1. Role

This directory contains basic I/O utility testcase sources, principally payload serialization/deserialization and QUIC-specific payload encoding.

## 2. Test model

The directory has two complementary coverage paths: `testcase_payload.cpp` tests fixed-width fields, arbitrary-length byte fields, group activation, length references, and 24-bit helpers; `testcase_payload_quic.cpp` tests `quic_encoded` values and QUIC variable-length data through the same payload abstraction.

## 3. Example: payload and QUIC variable-length integer

### Field layout, inferred length, and group control

`testcase_payload.cpp` first writes a field sequence containing a one-byte `padlen`, the bytes `data`, a big-endian 32-bit value `0x1000`, and a grouped `pad` field. Enabling the group produces `03 64 61 74 61 00 00 10 00 70 61 64`; disabling it omits the grouped length and padding fields and produces `64 61 74 61 00 00 10 00`. Assertions compare the complete serialized buffers with fixed expected bytes.

For parsing, the test registers `set_reference_value("pad", "padlen")`. The parsed length field determines the trailing `pad` size; the fixed-size 32-bit field is also known, so the remaining bytes can be assigned to `data`. The test checks each decoded field and writes the parsed layout back to bytes, comparing the round-trip result with the original input. Other cases exercise a header-dependent group and 24-bit integer conversion.

### QUIC variable-length integers

`testcase_payload_quic.cpp` uses `quic_encoded` as a payload member. It checks RFC 9000 Appendix A values across the 1-, 2-, 4-, and 8-byte encoding ranges, then reads the bytes back and verifies that the encoding is reproduced. String-backed values demonstrate the opaque length/data path; a second path uses `set_reference_value` to infer the byte-string lengths from encoded integer fields. The zero-length case is checked explicitly.

These are source-level known-answer and round-trip checks. They do not establish that every malformed or truncated payload is rejected correctly.

## 4. Test and verification status

### 4.1 Source-level coverage

The source directly checks payload output bytes, decoded field values, group selection, length references, 24-bit conversion, QUIC varint known-answer encodings and zero-length data. It does not provide a complete fuzzing or malformed/truncated-input robustness claim.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. The report has no separate `io/basic` row, so these counts must not be attributed to this directory alone. The report files do not independently identify the tested commit or exact build configuration. This documentation update did not rerun the tests.

## 5. Relationships

- Corresponding implementation documentation is under `sdk/io/`.
- [I/O testcase group](../README.md) — entry-point dispatch and aggregate `io` report.
- Shared test registration and build integration are defined by the surrounding testcase CMake configuration.

## 6. References

- `test/testcase/io/basic/testcase_payload.cpp`
- `test/testcase/io/basic/testcase_payload_quic.cpp`
