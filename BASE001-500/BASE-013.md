# BASE-013 — Thread testcase assertions and stream notes

- **Area:** `test/testcase/base/system`, `test/testcase/base/stream`
- **Status:** Open
- **Kind:** Focused testcase/documentation follow-up
- **Source basis:** Source-tree review on `docs/sdk-source-tree-review-1107`; no tests were run in this pass.

## Background

Two concrete notes remain outside the existing BASE-001..012 records:

1. `testcase_signalwait_threads.cpp` uses unconditional `assert(true, ...)` for the “threads created” and “msleep” messages. Those assertions do not establish that the preceding operations succeeded.
2. `testcase_stream.cpp::test_stream_split3()` retains a comment sketching `dtls_record_publisher::publish(tls_records*, ...)`. The comment may be historical/design context; it does not itself establish a production call path or a current dependency.
3. `testcase_bufferio.cpp::test_bufferio2()` retains a comment explaining that the case was intended to avoid passing a null `c_str()` result to output functions. This comment is not a complete API contract or a substitute for dedicated null-handling tests.

## Next check

1. Replace unconditional assertions only where the test can reliably observe a real operation result.
2. Decide whether the DTLS publisher sketch is still useful context; remove it if it no longer explains the testcase.
3. Preserve the null-pointer comment only if it describes the actual exercised path, and add a focused assertion if null handling is an intended behavior under test.
4. Keep changes local; this is not a request for a broad test-framework rewrite.

## History

- 2026-10-23: Consolidated source-level notes found in the base testcase docs. No tests changed or run.
