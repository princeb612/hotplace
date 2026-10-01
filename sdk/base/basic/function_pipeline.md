# Function Pipeline

`function_pipeline` provides sequential function execution controlled by a return/error state.

Its purpose is to make a chain of operations express whether later operations should run, whether failure handling should run, and whether cleanup/finalization must always run.

## Execution model

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

## Error categories

The pipeline is templated around an error/result category. The implementation includes handling for ordinary `return_t` values as well as categories such as OpenSSL errors and `errno`.

`result_to_return_t()` adapts the selected category into the project's common return representation.

This lets code with different error conventions participate in one execution-flow pattern without requiring every operation to use the same underlying API.

## Tracing and debugging

A tracer can be installed with `set_tracer()`. Debug builds can use `run_pipe()` to preserve file and line information and to generate pipeline-oriented diagnostic output.

These facilities are intended to explain why a later stage did or did not execute, rather than merely logging each function call.

## Tests

`test/testcase/base/basic/testcase_pipeline.cpp`

The testcase covers successful and failed execution paths, non-fatal continuation, exception-aware paths, and different error categories including OpenSSL and `errno` handling.

## Related source

- `sdk/base/basic/function_pipeline.hpp`
- `test/testcase/base/basic/testcase_pipeline.cpp`
