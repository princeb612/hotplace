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

# Stream Testcases

## 1. Role

This directory contains a focused testcase for the file-backed `file_stream` implementation. It exercises file sizing, memory mapping, mapped writes, and read-back through the stream API. It is not a general test of every stream operation or platform-specific error path.

## 2. Test model

- `testcase_filestream.cpp` — file open/truncate, memory-map lifecycle, data write, seek and read-back.
- The testcase creates a temporary file named `testfile` in the test working directory and removes it after the successful read assertion.

## 3. Example: mapped write followed by stream read

`test_filestream()` opens `testfile` with `open_write` and exits the guarded flow if open fails. It truncates the file to 1024 bytes and asserts the reported size. After `begin_mmap()`, it writes the 32-bit value `0x12345678` at four-byte intervals across the mapped range, then calls `end_mmap()` before using the stream API again.

The testcase seeks to `FILE_BEGIN`, reads four bytes into a `uint32`, and asserts that the value is `0x12345678`. The sequence checks a simple write-through-mapping/read-through-stream round trip and the required mapping end boundary. It does not verify every byte in the file, platform-specific mapping failures, concurrent access, or large-file behavior.

## 4. Test and verification status

### 4.1 Source-level coverage

The explicit assertions cover the truncated file size and first 32-bit read-back value. Open and mapping return statuses are recorded by the test harness and cause early exit on failure. The source does not assert the complete 1024-byte contents.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. The report has no separate `io/stream` row, so the parent totals must not be attributed to this testcase alone. The report does not independently identify the tested source commit or exact build configuration. This documentation update did not rerun the test.

## 5. Relationships

- `sdk/io/stream/` — file-backed stream implementation.
- `sdk/base/stream/` — shared in-memory stream abstractions.
- [I/O testcase group](../README.md) — aggregate `io` report and testcase registration.

## 6. References

- `testcase_filestream.cpp`
- `CMakeLists.txt`

## 7. Developer Notes

The testcase removes `testfile` on its normal successful path. When diagnosing an early failure, inspect the guarded cleanup path and test working directory rather than assuming the temporary file was always removed.
