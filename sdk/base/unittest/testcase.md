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

# Test Case

## 1. Role

test_case is the common test execution and result-reporting class used by hotplace test programs. It groups checks, records result codes and elapsed time, aggregates outcomes, prints reports, and returns process-level success/failure. It does not define the semantic meaning of each return_t value by itself: error_advisor supplies the category and presentation hint used by the reporting path.

## 2. Data Model

test_case accumulates individual records and statistics within a named group. A record retains the submitted result, function name, description, and elapsed time. The reporting code uses error_category_hint metadata—category, console color, compact testcase label, and long label—to interpret and present each result.

## 3. Behavior Model

### The role of error_advisor

The relationship is a division of responsibility:

- error_advisor::error_code() and error_message() translate a result code into its symbolic name and human-readable message when a description exists.
- error_advisor::categoryof() classifies the result; hintof() returns the associated display/reporting hint.
- test_case::vtest() stores the result and calls hintof(result) to select the aggregation and display path.
- The logger and console-color layer present the result; they do not replace the advisor's classification.

Typical categories include success (reported as pass), expected failure (reported as an expected outcome), severe error (fail), not supported and low security (skip), and trivial/warning outcomes. Consequently, the same reporting machinery can represent unsupported platform features and deliberately expected failures without treating every nonzero code as an unexpected test failure.

### Test lifecycle

```text
begin(group)
   ├─ test(return_t, ...)
   ├─ assert(condition, ...)
   ├─ ntest / nassert (expected-failure path)
   └─ timing controls
          ▼
       report() ─► result()
```

### Recording checks

begin() establishes the current named test group and resets the timing state. test(return_t, ...) records a supplied result code. assert(condition, ...) converts a false condition into errorcode_t::assert_failed and then uses the same result-recording path. ntest() and nassert() represent expected-failure behavior rather than simply reversing ordinary assertions.

The variadic APIs have v* counterparts (assert/vassert, test/vtest, nassert/vnassert, ntest/vntest) for the va_list path. The source notes this split as a workaround for Microsoft compiler variable-argument ambiguity.

### Timing and aggregation

Timing controls include reset_time(), pause_time(), and resume_time(). The implementation keeps stopwatch state per thread and protects shared state with a critical section. test_case_notimecheck provides an RAII pause/resume scope for setup or waits that should not dominate a measured test.

During result recording, the advisor's hint selects the category-specific counters and console style. report() presents the accumulated group and individual outcomes; report(top_count) can additionally list the slowest tests. result() converts the accumulated state to EXIT_SUCCESS when no unexpected failure was recorded and EXIT_FAILURE otherwise.

### Result-recording path

```text
assert(condition, ...)
  └─ false ─► errorcode_t::assert_failed
test(return_t, ...)
  └─ use supplied result
       │
       ▼
test_case::vtest()
  ├─ error_advisor classifies result
  ├─ update category counter / label / color
  ├─ retain test description and timing
  └─ report() ─► human-readable summary

result() ─► EXIT_SUCCESS if no unexpected failure; otherwise EXIT_FAILURE
```

The result code remains the input to classification; the console label/color is derived reporting metadata. The outer test runner consumes the executable's exit status, not the logger text or the visual category alone.

## 4. Relationships

- [Error handling and error advice](../system/error-handling.md) — result-code descriptions, category classification, and report hints.
- [Trace and debug events](../system/trace.md) — leave-trace paths and debug diagnostics.
- sdk/base/unittest/logger.hpp — output destination used by testcase reporting.
- sdk/base/unittest/console_color.hpp — console color presentation.
- `testcase.hpp/.cpp` implement result recording and reporting; `logger.hpp` and `console_color.hpp` provide output integration. `error.hpp` and `error_advisor.cpp` provide result/category interpretation.
- `test/testcase/base/unittest/testcase_unittest.cpp` — `test_error()` checks advisor name/message lookup; `test_testcase()` submits representative result categories; `test_fail()`, `test_trace()`, and `test_try_leave()` cover error-flow and leave-trace paths. This describes source coverage, not execution in this documentation task.
