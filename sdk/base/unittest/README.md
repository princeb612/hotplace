## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Unit Test Support

## 1. Role

`sdk/base/unittest` supplies the common test-result and diagnostic-output infrastructure used by hotplace test programs. Its two central components have separate responsibilities: `test_case` records test outcomes and produces a process-level result; `logger` formats and routes diagnostic messages.

This directory is project test infrastructure. It is not the same thing as CTest itself: CTest launches and records test executables, while `test_case` manages the assertions/results inside a hotplace test program.

## 2. Data Model

```text
test program
  ├─ test_case
  │    ├─ named group and individual records
  │    ├─ result-category counters and timing
  │    └─ report/result state
  └─ logger
       ├─ per-thread message context
       ├─ level and destination configuration
       └─ consumer/buffering and output settings
```

## 3. Behavior Model

### Execution and diagnostic paths

```text
test_case
  ├─ begin(group) ─► initialize group/result counters
  ├─ test / assert ─► classify check ─► update counters and timing
  ├─ report() ─────► render accumulated results
  └─ result() ─────► process exit status ─► test runner / CTest

logger
  ├─ builder configuration ─► logger instance / consumer
  ├─ level filter ──────────► accept or suppress message
  ├─ format / dump ─────────► buffered message
  └─ consumer ──────────────► console or file ─► flush / rotation
```

The two paths can meet when a test case emits diagnostics through a logger, but they remain independent: logging a message does not update the test result, and the test runner sees the process result rather than interpreting log text as pass/fail evidence.

- **Separate responsibilities:** `test_case` determines test outcomes; `logger` makes diagnostic information visible. A message being logged does not itself mark a test as passed or failed.
- **Result categories:** the test framework distinguishes ordinary success/failure from states such as not-supported and low-security, and offers expected-failure forms. Tests should use the intended category rather than disguising a known limitation as an ordinary pass.
- **Timing:** test timing can be paused/resumed or excluded through `test_case_notimecheck`. Be careful when comparing timing values across environments; setup, scheduling, and platform differences affect measurements.
- **Output buffering:** logger configuration includes a consumer interval, flush time/size, and file-rotation options. Callers requiring pending output to be processed can use the explicit flush API.
- **Concurrency:** the logger has per-thread context and a consumer path. Changes to buffering, shutdown, or shared state should be checked for lifetime and synchronization implications.
- **Historical material:** older logger sketches in this directory are retained as design/history material. They should not be treated as the current implementation contract without comparison to the active `.hpp/.cpp` files.

## 4. Relationships

### Test-result path

[`testcase.md`](testcase.md) explains the lifecycle from opening a named group through recording checks and generating a report. The `result()` return value allows the test executable to expose its accumulated status to the surrounding build/test runner.

### Diagnostic path

[`logger.md`](logger.md) explains how callers send messages without needing to know whether the configured destination is stdout or a file. Builder configuration controls output destinations and buffering/rotation options; log-level filtering is a separate concern from pass/fail accounting.

- `test_case` may attach a `logger` for diagnostics, but test outcome tracking remains a separate responsibility.
- The test executable's `main`/test harness uses `test_case::result()` to return a process status; CTest consumes the executable result at a higher level.
- `logger` uses common formatting and dump facilities, including `basic_stream` and memory-dump helpers from `sdk/base`.
- Testcase analysis documents under [`test/testcase/base/unittest/`](../../../test/testcase/base/unittest/README.md) explain test intent and report context; this README explains the implementation components that support those tests. The focused sources are `testcase_unittest.cpp`, `testcase_loglevel.cpp`, and `testcase_consolecolor.cpp`.
