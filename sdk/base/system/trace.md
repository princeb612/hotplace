# Trace and debug events

`trace.hpp` provides hotplace's lightweight debug tracing mechanism. It is closely tied to the project's `return_t`-based control-flow macros and logging infrastructure.

## Leave-trace helpers

In debug builds, helpers such as:

- `__trace`
- `__trace_return`
- `__leave2_trace`
- `__leave2_tracef`
- `__leave2_if_fail`

record the source location and return code while following the project's `__try2` / `__leave2` style of error propagation.

In non-debug builds the tracing overhead is reduced to the corresponding control-flow operation.

## Event tracing

The event API allows code to emit structured debug events using a category and event identifier:

- `set_trace_debug()` installs a consumer callback.
- `trace_debug_event*()` emits stream, formatted, or callback-generated content.
- `trace_debug_filter()` controls category filtering.
- `set_trace_level()` / `check_trace_level()` control verbosity.

A typical consumer resolves the numeric category/event through `trace_advisor` and writes the resulting names and message to the project's logger.

```text
producer
   |
   v
trace_debug_event(category, event, message)
   |
   v
registered debug handler
   |
   +--> trace_advisor : category/event name
   |
   v
logger / diagnostic output
```

## `trace_advisor`

`trace_advisor` maintains the mapping from trace categories/events to readable names. It is protected by the same `critical_section` abstraction used elsewhere in the system layer.

This separates event identifiers used by source code from their presentation names.

## Role in the project

Trace is not a general logging replacement. The logger/testcase layer handles ordinary output, while this layer provides conditional, category-aware diagnostics useful when following internal control flow and failures.
