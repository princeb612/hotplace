# `function_pipeline` - published by Gemini

## 1. Overview & Key Features

The `function_pipeline` module is a C++11 class template based on the Chain Pattern, designed to chain multi-step tasks (function calls) via a Fluent Interface (Method Chaining). It controls sequential execution upon errors and cleanly encapsulates resource release (rollback) and exception handling.

* **Fluent Interface (Method Chaining)**: Enables constructing an intuitive pipeline flow by chaining functions such as `.run()`, `.walk()`, and `.walk_failed()`.
* **Support for Diverse Return Types (C++11 Template)**: Supports custom types and error categories such as OpenSSL error codes (`int`, `osslerror_category`) in addition to the default return type `return_t`.
* **Conditional Execution Flow Evaluation**: Schedules execution based on a configured discriminant (`_discriminant`), advancing to the next step only on success, or executing only the rollback (`walk_failed`) phase upon failure.
* **Debugging & Trace Support**: Automatically reports the called filename (`__FILE__`), line number (`__LINE__`), processed step ratio (`processed / total`), and last error code to the trace system in `DEBUG` builds.

---

## 2. Key Implementation Areas & Technical Elements

* **Fluent Interface Chaining Mechanism**: Provides a declarative programming style that allows declaring a series of operations sequentially by leveraging self-referencing operators (returning `*this`).
* **Discriminant Evaluation-Based Conditional Branching**: Branches control flow based on internal discriminant states, executing the next step (`run`) only when previous execution results satisfy normal conditions.
* **Guaranteed Rollback & Cleanup Pattern**: Safely and cohesively manages rollback logic (`walk_failed`) executed on task failure, and garbage collection/release tasks (`walk_always`) executed regardless of success or failure at the pipeline level.
* **Exception Isolation**: Captures runtime exceptions occurring during external pipeline execution via `run_trycatch` statements, translating them into an internal pipeline error state (`value_exception`) to prevent abnormal system termination.

---

## 3. Major Data Structures, Classes & API Reference

### Template Definition

```cpp
template <typename T = return_t, typename category = void>
class function_pipeline;

```

### Key Method Analysis

| Category | Method / Macro | Description |
| --- | --- | --- |
| **Parameter Validation** | `test_parameter(checker)` | Executes pre-validation lambda. Sets `value_invalid_parameter()` on failure. |
| **Condition Setup** | `goahead_if_success()`<br><br>`goahead_if_not_fail()` | Changes evaluation criteria to proceed with next task when successful or non-fatal error occurs. |
| **Core Execution** | `run(func)`<br><br>`run_pipe(lambda)` | Executes core logic (function). Performed only when the preceding operation succeeds. |
| **Exception-Safe Execution** | `run_trycatch(func)` | Sets `value_exception()` and halts pipeline when an exception occurs. |
| **Side Work (Walk)** | `walk(func)`<br><br>`walk_failed(func)` | Executes auxiliary operations without return values. `walk_failed` executes on preceding task failure (for rollback). |
| **Result Retrieval** | `result()` / `passed()`<br><br>`result_to_return_t()` | Retrieves final return code and checks success status. Supports format conversion to `return_t`. |

---

## 4. Operational Principles

1. **Parameter & Pre-processing Validation**: Executes `test_parameter()` to perform validity checks; if validation fails, subsequent pipeline execution is immediately blocked and transitioned to a parameter error state.
2. **Pipeline Step Traversal**: Evaluates return values of previous steps based on the designated discrimination policy (`_discriminant`) when calling `run()`. Executes registered lambda functions when conditions are met, and implicitly skips execution of subsequent `run()` functions upon error.
3. **Error Detection & Rollback Execution**: If an error occurs in intermediate steps, the pipeline state transitions to failure, triggering execution of blocking, release, and rollback logic registered in `walk_failed()`.
4. **Final Settlement & Tracing**: Performs common resource cleanup tasks registered in `walk_always()` upon pipeline completion, settling executed steps and success status to convert into a final return code (`return_t`).

---

## 5. Usage Example (C++11 Standard)

```cpp
#include <iostream>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>

// Dummy target class for testing pipeline
class resource_manager {
public:
    hotplace::return_t initialize() {
        // Assume initialization succeeded
        return hotplace::errorcode_t::success;
    }

    hotplace::return_t process_step1() {
        // Step 1 logic
        return hotplace::errorcode_t::success;
    }

    hotplace::return_t process_step2() {
        // Step 2 failed example
        return hotplace::errorcode_t::internal_error;
    }

    void rollback() {
        // Rollback operations on failure
        std::cout << "[Rollback] Reverting changes due to pipeline failure.\n";
    }
};

int main() {
    using namespace hotplace;

    resource_manager res;
    int* ptr = &res ? new int(10) : nullptr;

    // Create pipeline instance (C++11 based)
    function_pipeline<return_t> pipeline;

    pipeline.test_parameter([&]() -> bool {
                // Check initial argument validity
                return (nullptr != ptr);
            })
            .goahead_if_success()
            .walk([&]() -> void {
                // Logging or side-effect work before execution
                std::cout << "[Pipeline] Starting sequence...\n";
            })
            .run([&]() -> return_t {
                return res.initialize();
            })
            .run([&]() -> return_t {
                return res.process_step1();
            })
            .run([&]() -> return_t {
                return res.process_step2();
            })
            .walk_failed([&]() -> void {
                // Executes only if any preceding step fails
                res.rollback();
            })
            .walk_always([&]() -> void {
                // Always clean up dynamic memory regardless of success/failure
                if (ptr) {
                    delete ptr;
                    ptr = nullptr;
                }
            });

    std::cout << "Processed steps: " << pipeline.processed() << " / " << pipeline.size() << std::endl;
    std::cout << "Pipeline passed: " << (pipeline.passed() ? "true" : "false") << std::endl;

    return pipeline.result_to_return_t();
}

```

---

## 6. TODO List

| ID | Priority | Task Description | Status | Remarks |
| --- | --- | --- | --- | --- |
| **TODO-FP-01** | `HIGH` | **Review C++11 `std::move` based lambda capture performance optimization**<br><br>- Prevent bypass of high copy-cost objects and expand rvalue reference utilization. | `To Do` | Refactor `runner` structure |
| **TODO-FP-02** | `HIGH` | **Verify `run_pipe` macro consistency in DEBUG mode**<br><br>- Inspect missing `__FILE__` and `__LINE__` tracking sections and verify interface alignment with non-debug builds. | `In Progress` | `set_tracer` and `handle_result` |
| **TODO-FP-03** | `MEDIUM` | **Design asynchronous/Future-compatible pipeline extension**<br><br>- Investigate feasibility of combining `std::future` / async lambda patterns. | `To Do` | Consider for future versions |
| **TODO-FP-04** | `MEDIUM` | **Expand C++11 error category trait**<br><br>- Register additional custom error types in `error_traits` template and write conversion unit tests. | `To Do` | Add beyond `osslerror_category` |

---
