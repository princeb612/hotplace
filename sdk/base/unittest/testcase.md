# Unit Test - published by Gemini

## 1. Overview and Architecture

The `test_case` module is a unit test library designed to systematically execute unit tests and aggregate/report results within C++ environments. It supports per-thread test case management and stopwatch (time measurement) functionality in multithreaded environments.

### Key Features

1. **Per-Thread Context Management**:
* Uses thread IDs (`arch_t tid`) as keys to independently manage test case names (`_testcase_per_threads`), stopwatch flags (`_time_flag_per_threads`), timestamps (`_timestamp_per_threads`), and slice durations (`_time_slice_per_threads`).
2. **RAII Timer Control**:
* Provides `reset_time()`, `pause_time()`, `resume_time()`, and `check_time()` to precisely measure target code segments.
* Automatically pauses and resumes time measurements for non-essential execution blocks (e.g., setup/teardown logic) using the RAII-based `test_case_notimecheck` scope guard.
3. **ANSI Color-Formatted Stream Binder (`t_stream_binder`)**:
* Wraps `console_color` and `basic_stream` to apply terminal text styles and colors (success/failure/warning, etc.) during console output.
4. **Comprehensive Assertions and Result Classification**:
* Provides various assertion interfaces such as `assert`, `vassert`, `nassert`, `test`, and `ntest`.
* Automatically categorizes assertion results via the `error_advisor` system into groups like `success`, `expect_failure`, `severe`, `not_supported`, `trivial`, and `warn`.
5. **Comprehensive Reporting (`report`)**:
* Supports console/logger output and saving results to a `report` file.
* Generates pass/fail statistics per test group, detailed failure lists, and Top-N execution time reports.

---

## 2. Core Classes and API Reference

### Key Components

* **`test_case`**: The main class responsible for test grouping, timer control, result verification, statistical aggregation, and report generation.
* **`test_case_notimecheck`**: An RAII helper class that automatically pauses and resumes `test_case` time measurements within a specific scope.
* **`t_stream_binder<STREAM_T, BINDER>`**: A template stream processing wrapper that writes string and color binder data into a stream buffer.

### Key Methods

| Class / Method | Description |
| --- | --- |
| **`test_case::begin`** | Starts a new test case group and initializes per-thread timestamps and timers. |
| **`test_case::pause_time` / `resume_time**` | Pauses or resumes per-thread stopwatches for precise segment timing. |
| **`test_case::assert` / `vassert**` | Verifies boolean conditions (`bool`) and records test results (supports variadic format parameters). |
| **`test_case::nassert` / `vnassert**` | Verifies negative assertions (conditions expected to fail). |
| **`test_case::test` / `vtest**` | Accepts a `return_t` error code directly, evaluates success/failure based on `error_advisor`, and records the result. |
| **`test_case::report`** | Outputs overall test results, failure details, and top execution times (Top-N) to console/logger and file. |
| **`test_case::result`** | Returns `internal_error` if one or more failures exist (`_count_fail > 0`), otherwise returns `success`. |
| **`test_case::attach`** | Binds a logging system (`logger`) instance to direct test results to the logger stream. |

---

## 3. Core Internal Architecture

### 3.1. Stopwatch Timing Pipeline

The execution flow of the per-thread stopwatch during testing:

```
begin() / reset_time()
  │
  ├─► _time_flag_per_threads[tid] = true
  ├─► _timestamp_per_threads[tid] = monotonic_now()
  └─► _time_slice_per_threads[tid].clear()
  │
  ▼ [When excluded timing section occurs]
pause_time()   ──► Calculates diff(stamp, now), appends to _time_slice, flag = false
resume_time()  ──► stamp = monotonic_now(), flag = true
  │
  ▼
test() / assert() / check_time()
  │
  ├─► (If flag == true) Calculates remaining diff, appends to _time_slice
  ├─► Sums all slices (time_sum) -> Computes elapsed time
  └─► Creates unit test_item_t, records results, and calls reset_time() automatically

```

### 3.2. Result Aggregation and Categorization

Result codes are automatically categorized and processed statistically via `error_advisor`:

```
[Result return_t] ──► advisor->categoryof(result)
                           │
                           ├─► success / expect_failure ──► Increments _count_success (Cyan/Default)
                           ├─► severe                  ──► Increments _count_fail (Red)
                           ├─► not_supported           ──► Increments _count_not_supported (Cyan)
                           └─► trivial / warn / low    ──► Increments _count_trivial (Yellow)

```

---

## 4. C++11 Usage Example

```cpp
#include <iostream>
#include <thread>
#include <hotplace/sdk/base/unittest/testcase.hpp>

// Dummy test functions
hotplace::return_t sample_success_function() {
    return hotplace::errorcode_t::success;
}

hotplace::return_t sample_fail_function() {
    return hotplace::errorcode_t::assert_failed;
}

void run_unit_test_demo() {
    using namespace hotplace;

    test_case tc;

    // -------------------------------------------------------------
    // Group 1: Basic Assertions & Time Exclusion
    // -------------------------------------------------------------
    tc.begin("Basic Logic Test Group");

    // General boolean assertion
    tc.assert(1 + 1 == 2, __FUNCTION__, "Verify simple math addition");

    // Measure time excluding preparation block using RAII guard
    {
        test_case_notimecheck guard(tc);
        // Time consumed in this block will not be calculated
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Negative assertion (Expecting false)
    tc.nassert(1 == 2, __FUNCTION__, "Verify negative condition expectation");

    // -------------------------------------------------------------
    // Group 2: Errorcode Verification
    // -------------------------------------------------------------
    tc.begin("Return Code Test Group");

    return_t ret_success = sample_success_function();
    tc.test(ret_success, "sample_success_function", "Check success result code");

    // Intentionally testing a failing case
    return_t ret_fail = sample_fail_function();
    tc.test(ret_fail, "sample_fail_function", "Check intentional failure code");

    // -------------------------------------------------------------
    // Group 3: Reporting & Final Result
    // -------------------------------------------------------------
    // Display summary and top 5 execution time cases
    tc.report(5);

    if (tc.result() == errorcode_t::success) {
        std::cout << "All test cases passed successfully." << std::endl;
    } else {
        std::cout << "Some test cases failed. Please check report file." << std::endl;
    }
}

int main() {
    run_unit_test_demo();
    return 0;
}

```

---

## 5. TODO List Tracker

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| ~~**TODO-TC-01**~~ | `HIGH` | **Validate `test_case::begin` concurrency and thread safety**<br><br>- Verified thread isolation for `topic` formatting and scope protection for `_testcase_per_threads` guard | `No change required` | `testcase.cpp`<br> |
| **TODO-TC-02** | `MEDIUM` | **Add JSON / XML format report file export options**<br><br>- Implement structured format output mechanisms for CI/CD pipeline integration (Jenkins, GitHub Actions) | `To Do` | Extend `report()` function |
