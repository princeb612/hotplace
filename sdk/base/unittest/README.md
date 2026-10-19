## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
└──────────────────────────────────────────────┘
```

# Unit Test Support

## 1. Role

`sdk/base/unittest` supplies the common test-result and diagnostic-output infrastructure used by hotplace test programs. Its two central components have separate responsibilities: `test_case` records test outcomes and produces a process-level result; `logger` formats and routes diagnostic messages.

This directory is project test infrastructure. It is not the same thing as CTest itself: CTest launches and records test executables, while `test_case` manages the assertions/results inside a hotplace test program.

## 2. Model

```text
test program
    │
    ├── test_case
    │     ├── begin / test / assert
    │     ├── result categories and statistics
    │     ├── report()
    │     └── result() ─────────► process exit status
    │
    └── logger
          ├── formatting / stream input
          ├── log-level filtering
          ├── console and file output
          ├── binary dump / console color
          └── buffered output / consumer
```

### Test-result path

[`testcase.md`](testcase.md) explains the lifecycle from opening a named group through recording checks and generating a report. The `result()` return value allows the test executable to expose its accumulated status to the surrounding build/test runner.

### Diagnostic path

[`logger.md`](logger.md) explains how callers send messages without needing to know whether the configured destination is stdout or a file. Builder configuration controls output destinations and buffering/rotation options; log-level filtering is a separate concern from pass/fail accounting.

## 3. Important behavior and lifetime

- **Separate responsibilities:** `test_case` determines test outcomes; `logger` makes diagnostic information visible. A message being logged does not itself mark a test as passed or failed.
- **Result categories:** the test framework distinguishes ordinary success/failure from states such as not-supported and low-security, and offers expected-failure forms. Tests should use the intended category rather than disguising a known limitation as an ordinary pass.
- **Timing:** test timing can be paused/resumed or excluded through `test_case_notimecheck`. Be careful when comparing timing values across environments; setup, scheduling, and platform differences affect measurements.
- **Output buffering:** logger configuration includes a consumer interval, flush time/size, and file-rotation options. Callers requiring pending output to be processed can use the explicit flush API.
- **Concurrency:** the logger has per-thread context and a consumer path. Changes to buffering, shutdown, or shared state should be checked for lifetime and synchronization implications.
- **Historical material:** older logger sketches in this directory are retained as design/history material. They should not be treated as the current implementation contract without comparison to the active `.hpp/.cpp` files.

## 4. Example from the source tests

### Recording result categories

`test/testcase/base/unittest/testcase_unittest.cpp` opens the `"test_case"` group, records a success, a not-supported result, and a low-security result, then records another success. Optional timing-check logic uses `test_case_notimecheck` around a deliberate wait. The report and final result are handled by the shared test harness.

This example shows that a test record is more than a Boolean: the result category affects how the report describes the outcome.

### Logger filtering

`test/testcase/base/unittest/testcase_loglevel.cpp` exercises explicit and implicit log-level behavior. Read it alongside the filtering section in [`logger.md`](logger.md) to follow the distinction between the configured threshold and the level used when a message does not provide one.

### Trace through the source

```text
testcase_unittest.cpp
    ├── _test_case.begin(...)
    ├── _test_case.test(...) / assert(...)
    ├── _test_case.report()
    └── _test_case.result()

testcase_loglevel.cpp
    └── logger level configuration
          └── emitted vs. suppressed messages
```

## 5. Relationships

- `test_case` may attach a `logger` for diagnostics, but test outcome tracking remains a separate responsibility.
- The test executable's `main`/test harness uses `test_case::result()` to return a process status; CTest consumes the executable result at a higher level.
- `logger` uses common formatting and dump facilities, including `basic_stream` and memory-dump helpers from `sdk/base`.
- Testcase analysis documents under `test/testcase/` explain test intent and report context; this README explains the implementation components that support those tests.

## 6. References

### Implementation

- `sdk/base/unittest/testcase.hpp`
- `sdk/base/unittest/testcase.cpp`
- `sdk/base/unittest/logger.hpp`
- `sdk/base/unittest/logger.cpp`
- `sdk/base/unittest/logger_builder.cpp`
- `sdk/base/unittest/logger_write.cpp`
- `sdk/base/unittest/logger_dump.cpp`
- `sdk/base/unittest/console_color.hpp`
- `sdk/base/unittest/types.hpp`

### Tests

- `test/testcase/base/unittest/testcase_unittest.cpp`
- `test/testcase/base/unittest/testcase_loglevel.cpp`
- `test/testcase/base/unittest/testcase_consolecolor.cpp`
- [Testcase analysis](../../../test/testcase/base/unittest/testcase_unittest.md)
