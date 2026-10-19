## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Test Case

## 1. Role

### Introduction

`test_case` is the common test execution and result-reporting class used by hotplace test programs.

It provides more than a simple assertion macro: a test program can create named test groups, record individual results, measure execution time, classify failures, print a report, and return a process-level success/failure result.

## 2. Model

### Test lifecycle

```text
begin(group)
   │
   ├── test(return_t, ...)
   ├── assert(condition, ...)
   ├── ntest / nassert (expected-failure path)
   └── timing controls
          │
          ▼
       report()
          │
          ▼
       result()
```

`test_case` accumulates individual records and statistics within a named group. The public API includes ordinary checks and variants for expected failures or other result categories. `report()` presents the recorded state; `result()` converts it to the process-level status used by the executable.

### Record and report data

A recorded check can include the outcome/error code, function name, description, and elapsed time. The report can summarize the group and list failed or slow tests. These are reporting semantics: the class records what the testcase tells it, so a weak assertion can still be recorded as a pass.

### Variadic API pairs

The ordinary formatting-oriented calls have `v*` counterparts (`assert`/`vassert`, `test`/`vtest`, `nassert`/`vnassert`, `ntest`/`vntest`). The source documents these pairs as a workaround for Microsoft compiler variable-argument ambiguity. Preserve this distinction when changing overloads or cross-compiler behavior.

## 3. Important behavior and lifetime

### Basic flow

The intended usage is centered on `begin()`, `test()` or `assert()`, `report()`, and `result()`.

```text
 test_case
     │
     ├── begin("group")
     │     ├── test(...)
     │     ├── assert(...)
     │     └── ntest / nassert
     │
     ├── report()
     └── result()
```

A typical test program therefore has the shape:

```cpp
test_case tc;
tc.begin("example");
tc.test(errorcode_t::success, __FUNCTION__, "basic case");
tc.assert(condition, __FUNCTION__, "condition");
tc.report();
return tc.result();
```

### Timing

`test_case` measures test execution time as part of the test record.

Timing can be controlled with:

- `reset_time()`
- `pause_time()`
- `resume_time()`

`test_case_notimecheck` wraps the common pause/resume pattern with RAII:

```cpp
{
    test_case_notimecheck block(tc);
    // work here is excluded from the test-time measurement
}
```

This is useful when a test deliberately waits or performs setup that should not dominate the measured operation.

The timing state is maintained per thread, which allows test code running on multiple threads to retain separate timing information.

### Reports

`report()` produces the accumulated test report.

The report can include:

- test-group status
- individual test result and error code
- function and description
- elapsed time
- failed tests
- timing information

`report(top_count)` can additionally list the slowest tests, making the test framework useful for identifying unexpectedly expensive cases as well as functional failures.

### Final result

`result()` converts the accumulated test state into a process-level result:

```text
EXIT_SUCCESS  → all required tests passed
EXIT_FAILURE  → an unexpected failure was recorded
```

This allows the same test object to drive both the human-readable report and the return value consumed by the test executable/CTest environment.

### Variadic interface

The formatted test APIs have both ordinary and `va_list` forms:

```text
assert()   → vassert()
test()     → vtest()
nassert()  → vnassert()
ntest()    → vntest()
```

The source documents this distinction as a workaround for Microsoft compiler variable-argument ambiguity. The `v*` forms therefore form part of the implementation interface rather than being redundant convenience functions.

## 4. Example from the source tests

### Test groups and results

`begin()` starts a named test group and resets the timing state for the current thread.

Individual checks are recorded with either:

- `test(return_t, ...)`
- `assert(bool, ...)`
- `ntest(return_t, ...)`
- `nassert(bool, ...)`

The `n*` forms are for **expected failure** cases. They allow a test to document behavior that is intentionally expected to fail without treating that result as an unexpected regression.

The internal statistics distinguish successful, expected-failure, failed, not-supported, low-security, and trivial cases.

### Test examples

The direct testcase is:

`test/testcase/base/unittest/testcase_unittest.cpp`

It demonstrates:

- successful and skipped tests
- low-security results
- intentional failure paths
- `assert()` usage
- formatted messages
- `test_case_notimecheck`
- failure/trace helpers used around the test framework
- error-code reporting

`testcase_loglevel.cpp` exercises the logger side of the framework and verifies the filtering rules used by attached logging.

## 5. Relationships

### Logger integration

A `test_case` can attach a `logger` instance.

```text
 test_case
     │
     ├── test result / statistics
     ├── report
     └── logger
          └── diagnostic output
```

This keeps test semantics separate from output formatting while allowing the report and diagnostic messages to use the project's common logging infrastructure.

## 6. References

### Related source

- `sdk/base/unittest/testcase.hpp`
- `sdk/base/unittest/testcase.cpp`
- `sdk/base/unittest/logger.hpp`
- `test/testcase/base/unittest/testcase_unittest.cpp`
- `test/testcase/base/unittest/testcase_loglevel.cpp`
