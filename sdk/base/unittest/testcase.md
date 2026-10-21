## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Test Case

## 1. Role

test_case is the common test execution and result-reporting class used by hotplace test programs. It groups checks, records result codes and elapsed time, aggregates outcomes, prints reports, and returns process-level success/failure. It does not define the semantic meaning of each return_t value by itself: error_advisor supplies the category and presentation hint used by the reporting path.

## 2. Data Model

### Test lifecycle

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

test_case accumulates individual records and statistics within a named group. A record retains the submitted result, function name, description, and elapsed time. The reporting code uses error_category_hint metadata—category, console color, compact testcase label, and long label—to interpret and present each result.

### The role of error_advisor

The relationship is a division of responsibility:

- error_advisor::error_code() and error_message() translate a result code into its symbolic name and human-readable message when a description exists.
- error_advisor::categoryof() classifies the result; hintof() returns the associated display/reporting hint.
- test_case::vtest() stores the result and calls hintof(result) to select the aggregation and display path.
- The logger and console-color layer present the result; they do not replace the advisor's classification.

Typical categories include success (reported as pass), expected failure (reported as an expected outcome), severe error (fail), not supported and low security (skip), and trivial/warning outcomes. Consequently, the same reporting machinery can represent unsupported platform features and deliberately expected failures without treating every nonzero code as an unexpected test failure.

## 3. Behavior Model

### Recording checks

begin() establishes the current named test group and resets the timing state. test(return_t, ...) records a supplied result code. assert(condition, ...) converts a false condition into errorcode_t::assert_failed and then uses the same result-recording path. ntest() and nassert() represent expected-failure behavior rather than simply reversing ordinary assertions.

The variadic APIs have v* counterparts (assert/vassert, test/vtest, nassert/vnassert, ntest/vntest) for the va_list path. The source notes this split as a workaround for Microsoft compiler variable-argument ambiguity.

### Timing and aggregation

Timing controls include reset_time(), pause_time(), and resume_time(). The implementation keeps stopwatch state per thread and protects shared state with a critical section. test_case_notimecheck provides an RAII pause/resume scope for setup or waits that should not dominate a measured test.

During result recording, the advisor's hint selects the category-specific counters and console style. report() presents the accumulated group and individual outcomes; report(top_count) can additionally list the slowest tests. result() converts the accumulated state to EXIT_SUCCESS when no unexpected failure was recorded and EXIT_FAILURE otherwise.

### Source testcase connecting the two layers

test/testcase/base/unittest/testcase_unittest.cpp contains test_error(): it obtains error_advisor::get_instance(), asks for the symbolic code and message of errorcode_t::invalid_parameter, and writes both to the logger. The same file's test_testcase() submits success, not-supported, and low-security results to exercise representative report categories; test_fail(), test_trace(), and test_try_leave() cover error-flow and leave-trace paths.

These statements describe what the source testcase contains. They do not assert that the testcase was executed in this documentation pass.

## 4. Relationships

- [Error handling and error advice](../system/error-handling.md) — result-code descriptions, category classification, and report hints.
- [Trace and debug events](../system/trace.md) — leave-trace paths and debug diagnostics.
- sdk/base/unittest/logger.hpp — output destination used by testcase reporting.
- sdk/base/unittest/console_color.hpp — console color presentation.
- `testcase.hpp/.cpp` implement result recording and reporting; `logger.hpp` and `console_color.hpp` provide output integration. `error.hpp` and `error_advisor.cpp` provide result/category interpretation. `testcase_unittest.cpp` exercises direct advisor lookup and representative result-category use.
