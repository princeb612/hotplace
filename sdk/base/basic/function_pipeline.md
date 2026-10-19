## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Function Pipeline

## 1. Role

### Introduction

`function_pipeline` provides sequential function execution controlled by a return/error state.

Its purpose is to make a chain of operations express whether later operations should run, whether failure handling should run, and whether cleanup/finalization must always run.

## 2. Model

### Execution model

The main operations are:

- `run()` — execute a function as part of the normal pipeline
- `run_trycatch()` — execute with exception handling
- `run_failed()` — execute only when the pipeline is in a failed state
- `walk()` — execute a function while walking the pipeline state
- `walk_trycatch()` — exception-aware walk
- `walk_failed()` — walk only on failure
- `walk_always()` — execute regardless of the current state

Helpers such as `test_parameter()`, `goahead_if_success()`, and `goahead_if_not_fail()` make the condition explicit when a pipeline is assembled.

A `run_pipe()` macro also records source location information for debug-oriented tracing.

## 3. Important behavior and lifetime

### Error categories

The pipeline is templated around an error/result category. The implementation includes handling for ordinary `return_t` values as well as categories such as OpenSSL errors and `errno`.

`result_to_return_t()` adapts the selected category into the project's common return representation.

This lets code with different error conventions participate in one execution-flow pattern without requiring every operation to use the same underlying API.

### Tracing and debugging

A tracer can be installed with `set_tracer()`. Debug builds can use `run_pipe()` to preserve file and line information and to generate pipeline-oriented diagnostic output.

These facilities are intended to explain why a later stage did or did not execute, rather than merely logging each function call.

### Tests

`test/testcase/base/basic/testcase_pipeline.cpp`

The testcase covers successful and failed execution paths, non-fatal continuation, exception-aware paths, and different error categories including OpenSSL and `errno` handling.

## 4. Example from the source tests

### Test walkthrough

`test/testcase/base/basic/testcase_pipeline.cpp` builds a pipeline whose callbacks append labels to a `path` string. It validates parameters, runs a normal step that adds two `bignumber` values, and then includes a failure-only step and an always-run final step.

```text
test_parameter
      │
      ▼
    walk
      │
      ▼
   run_pipe (calculation / return code)
      │
      ├── success path: ordinary steps continue
      └── failed state: failure-only step may run
      │
      ▼
  walk_always (final marker)
```

The recorded path is the observable evidence for control-flow behavior. When editing the pipeline, compare both the final `result()` and the callback sequence; a final error code alone may not show which conditional steps executed.

## 5. Relationships

- Pipeline steps retain their own return/error contracts; the pipeline decides whether later callbacks run based on the current state.
- `run_pipe()` connects the execution flow with source-location-oriented tracing.
- A pipeline can be used by higher-level components without making those components depend on a specific protocol.

## 6. References

### Related source and tests

- Implementation: `sdk/base/basic/function_pipeline.hpp`
- Test: `test/testcase/base/basic/testcase_pipeline.cpp`

