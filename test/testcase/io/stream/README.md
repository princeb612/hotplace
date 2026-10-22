## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# Stream testcases

## 1. What

The stream testcase exercises `file_stream` through a temporary file: open/truncate, memory-map, write into the mapped region, end the mapping, seek to the beginning, and read back one 32-bit value. It is a narrow write/read integration case, not a full file-stream API or failure-path suite.

## 2. How

### 2.1 Mapped write and stream read-back

1. **Entry:** `testcase_filestream() → test_filestream()` in `testcase_filestream.cpp`.

2. **Preparation and operation sequence**

1. Create a `file_stream` and use the filename `testfile` in the test working directory.
2. Open it for writing. The guarded flow exits if opening fails.
3. Truncate the file to 1024 bytes and assert that the reported size is 1024.
4. Begin a memory mapping. The mapping status is recorded through the testcase harness; failure prevents the subsequent mapped write path.
5. Write a sequence of 32-bit values through the mapped pointer at four-byte intervals. The first value is `0x12345678`; later positions are populated with the loop index.
6. End the mapping before switching back to the stream API.
7. Seek to `FILE_BEGIN`, read four bytes into a `uint32`, and assert that the value equals `0x12345678`.
8. Remove `testfile` on the normal successful path.

3. **What the assertions establish:** the file's reported truncated size and the first 32-bit value's visibility through the stream read path after a mapped write. The testcase does not compare all 1024 bytes, validate all loop-written values, test concurrent mapping, or systematically inject open/map/read failures. The read assertion is host-endian sensitive because the test writes a native integer through the mapped pointer and reads it back as a native integer; it is not a portable on-disk byte-order test.

4. **Cleanup boundary:** because deletion occurs in the normal flow, an early failure can leave `testfile` in the working directory. A leftover file alone does not prove the testcase passed or failed.

## 3. Evidence

### Source-level coverage

**Mapped file write/read-back**

```text
create/truncate file -> assert file size == 1024
  -> map file -> write native 32-bit values
  -> unmap -> seek to offset 0 -> read one value
  -> assert first value == 0x12345678
```

This proves the first mapped write is visible through the stream read API. The other loop-written values are not compared, so this is neither a full-file byte check nor a portable byte-order test. Cleanup is on the normal path; early failure may leave the temporary file. The aggregate I/O report has no per-stream result row.



The shared [Test Report Snapshot](../../test-report-status.md) contains only the aggregate `io` result and no separate stream row. It must not be interpreted as a per-test result for this one mapping case. The snapshot's associated run context is Revision 1104 · MinGW64/GCC · CTest; the exact tested commit and complete build details are not independently recorded in the report files.

Source-level evidence consists of the 1024-byte size assertion and the read-back equality check. This documentation change did not execute the test.



## 4. Relationships

- `sdk/io/stream/` — file-backed stream implementation.
- `sdk/base/stream/` — shared in-memory stream abstractions.
- [I/O testcase suite](../README.md) — dispatch and aggregate report context.
- [`CMakeLists.txt`](../CMakeLists.txt) — target source collection.
- [`testcase_filestream.cpp`](testcase_filestream.cpp) — mapped write/read sequence.

## 5. References

No external reference is needed to explain this source-level round trip.

## 6. Developer Notes

When investigating a failed run, inspect the working directory for `testfile` and read the log around open, truncate, mapping, and read operations. The source's normal cleanup path is not evidence that cleanup ran after an early exit.
