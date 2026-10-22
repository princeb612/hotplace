## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Unit-test infrastructure testcases

## 1. What

These tests exercise the test framework and logger components in [`sdk/base/unittest`](../../../../sdk/base/unittest/README.md). The framework records testcase outcomes and provides control-flow/assertion helpers; the logger filters messages by explicit or implicit log level and emits terminal formatting. Console color output is presentation behavior, not the same contract as testcase result accounting.

## 2. How

### 2.1 Test result categories and assertions

1. In [`testcase_unittest.cpp`](testcase_unittest.cpp), `test_testcase()` opens the `test_case` group and records examples of `success`, `not_supported`, and `low_security`. The source comments identify these as pass, skip, and low/trivial categories. Intentional failure examples are commented out; their presence in comments is not an executed failing test.

2. The `test_fail()` path calls `function_always_fail()`, which returns `internal_error`. It then uses `__leave2_if_fail(ret)`; the `finally` block checks that the assignment after the leave point did not happen (`test == 0`). This is a concrete control-flow assertion.

3. By contrast, `test_trace()` and `test_try_leave()` exercise trace macros but finish with `assert(true, ...)`. Those assertions do not validate the trace text or formatted message. `test_error()` asks `error_advisor` for an error code and message and logs them, but contains no expected-string comparison. `test_except()` dereferences a null pointer; it is not invoked by `testcase_unittest()` in the shown source, so it must not be treated as an executed exception-handling test.

### 2.2 Logger level filtering

1. In [`testcase_loglevel.cpp`](testcase_loglevel.cpp), the test builds a list of trace, debug, info, warn, error, fatal, and notice levels. It iterates through each as the configured threshold and, for each threshold, tests every explicit message level.

2. The callback passed to `_logger->writeln()` sets `islogged = true` only if the message callback is invoked. The assertion compares this observation with `level >= _logger->get_loglevel()`. The implicit-level loop performs the analogous comparison against `get_implicit_loglevel()`. This is a direct behavioral check of callback invocation/filtering, not merely a visual inspection of terminal output.

3. The test resets both configured levels to the default before the loops and restores them to trace at the end. This reset behavior matters because logger configuration is shared state and could otherwise affect subsequent testcase output.

### 2.3 Console color output

1. In [`testcase_consolecolor.cpp`](testcase_consolecolor.cpp), the test iterates two background colors, six styles, and eight foreground colors, omitting combinations where foreground and background colors are equal. It emits styled `test` text and turns styling off after each fragment. A second pair of examples emits a yellow-on-black `color` label followed by `default`.

2. The final assertions are unconditional `assert(true, ...)`. They do not inspect terminal escape sequences or verify the rendered appearance. The loop exercises the combination-building and output path, but the result is diagnostic presentation rather than an expected-output test.

## 3. Evidence

### Source-level coverage

**1. Test result categories**

```text
assert / nassert / status / skip / trivial APIs
  -> record testcase outcome
  -> compare selected recorded result categories
```

Reported `skip` and `triv` categories remain distinct; they are not ordinary passes.

**2. Logger filtering and console color**

```text
emit messages at selected levels -> check asserted filter/status behavior
choose console style -> emit output -> terminal rendering not verified by report
```

**3. Trace output**

```text
enable trace -> emit diagnostic text -> unconditional assertion
  -> proves execution path only; does not compare trace contents
```



The supplied [Test Report Snapshot](../../test-report-status.md) records the `test_case`, `loglevel`, and `console_color` groups. Report categories such as `skip` and `triv` are preserved as distinct outcomes rather than being converted to pass.

The report does not independently identify the tested source revision, OS, compiler, or complete build configuration. A reported console-color group does not prove that the terminal rendered the styles as intended, and a trace testcase does not prove trace text correctness when its assertion is unconditional.



## 4. Relationships

- [`sdk/base/unittest/README.md`](../../../../sdk/base/unittest/README.md) — test framework and logger architecture.
- [`sdk/base/unittest/testcase.md`](../../../../sdk/base/unittest/testcase.md) — assertion and result semantics.
- [`sdk/base/unittest/logger.md`](../../../../sdk/base/unittest/logger.md) — logger filtering and output behavior.
- [`testcase_unittest.cpp`](testcase_unittest.cpp), [`testcase_loglevel.cpp`](testcase_loglevel.cpp), and [`testcase_consolecolor.cpp`](testcase_consolecolor.cpp) — direct testcase sources.
- [`../CMakeLists.txt`](../CMakeLists.txt) — base testcase source collection.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 5. References

No external reference is required to explain these testcase flows.
