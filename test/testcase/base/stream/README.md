## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Base Stream Testcases

## 1. Role

This directory contains testcase sources for the `sdk/base/stream` utilities. The notes document what the inspected source checks; they do not imply that every test was executed for revision 1104.

## 2. Test model

- `testcase_stream.cpp` registers the `stream` report group and exercises `basic_stream`, integer formatting, line extraction, auto-indentation, and splitter behavior.
- `testcase_bufferio.cpp` registers the `bufferio` report group and exercises buffered writes, search, edit, compare, clear, and pointer retrieval after clearing.
- `binary_stream` direct coverage was not found in these two source files and should not be inferred from tests of `binary_t` or other stream utilities.

```text
source testcase
      │
      ├── explicit expected-value assertions
      ├── operation-result checks
      └── diagnostic / smoke checks
                  │
                  ▼
       report snapshot (separate evidence)
```

## 3. Example: representative testcase flow

`test_stream_autoindent()` writes two lines after enabling two-space indentation and compares the result with the expected string `"  test\n  test"`. In contrast, `test_stream_vtprintf()` ends with an unconditional `assert(true, ...)`, so that assertion alone does not verify the formatted output.

## 4. Test and verification status

### 4.1 Source-level coverage

The per-file testcase notes distinguish explicit expected-value comparisons (`O`), partial or diagnostic-only checks (`△`), and unobserved checks (`X`). These ratings are about source-level evidence, not pass/fail outcomes.

### 4.2 Documentation and verification status

The supplied base report lists `stream` with 27 pass results and `bufferio` with 30 pass results, with no reported failures in those groups. The report does not identify the tested source revision, OS, compiler, or build configuration; it is not proof that these groups were run against revision 1104. See [test report status](../../test-report-status.md) for the report's scope.

## 5. Relationships

- [`testcase_stream.md`](testcase_stream.md) — source-level review of `testcase_stream.cpp`.
- [`testcase_bufferio.md`](testcase_bufferio.md) — source-level review of `testcase_bufferio.cpp`.
- [`sdk/base/stream/README.md`](../../../../sdk/base/stream/README.md) — module overview.

## 6. References

- Test sources: `test/testcase/base/stream/testcase_stream.cpp`, `test/testcase/base/stream/testcase_bufferio.cpp`.
- Report source: supplied `test/testcase/base/report` snapshot, whose execution environment and source revision are unspecified.
