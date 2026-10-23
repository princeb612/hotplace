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

# Trace and debug events

## 1. Role

The trace subsystem provides two related diagnostic paths: leave-trace helpers used by error-control macros, and explicit category/event debug messages emitted by source code. A key property of hotplace's design is that diagnostic calls can already exist inside implementation code while their delivery remains conditional. In a debug build, an application or testcase executable must enable the relevant runtime options and install a handler to make the event messages visible.

This is not the same as enabling ordinary logger verbosity. The logger is the destination for messages; trace options, trace level, and the registered callback control whether internal trace events reach it.

## 2. Data Model

- trace_category_t and trace_event_t identify the source/category and event.
- set_trace_debug() registers a callback receiving the category, event, and a stream_t* containing the formatted message.
- trace_debug_event_stream(), trace_debug_event_printf(), and trace_debug_event() support existing streams, printf-style messages, or callback-built basic_stream messages.
- trace_debug_filter() / trace_debug_filtered() provide per-category filtering.
- set_trace_level() and check_trace_level() control verbosity; the documented levels include loglevel_trace (0) and loglevel_debug (2).
- The root-level sdk/base/trace.hpp defines the option mask used by this system: trace_bt for backtrace, trace_except for exception tracing, and trace_debug for trace/debug events.

The trace_advisor maps category/event identifiers to readable names. The callback is responsible for the final output; a typical handler resolves those names and writes the stream to the configured logger.

## 3. Behavior Model

### Debug-build leave tracing

The __trace, __trace_return, __leave2_trace, __leave2_tracef, and __leave2_if_fail macros have debug-build implementations under #if defined DEBUG. They record source location and result information through leave_trace_dbg_print() / leave_trace_dbg_printf(); some variants also request a backtrace. In non-debug builds, these macros reduce to their control-flow action (such as return or break) and do not emit those diagnostics.

### Enabling the pre-existing debug messages

A debug build is necessary but not sufficient to display trace events. A sample executable's command-line setup shows the complete activation chain:

1. Under #if defined DEBUG, register options with the command-line parser:
   - -d: enable debug/trace mode;
   - -D <level>: set a numeric trace level (the option description identifies 0 or 2);
   - --trace: select loglevel_trace;
   - --debug: select loglevel_debug.
2. Parse the arguments, then inspect the resulting OPTION.
3. When option.debug is true, install a handler with set_trace_debug(). The sample handler forwards the stream to _logger->write(s).
4. Enable the option mask with set_trace_option(trace_bt | trace_except | trace_debug).
5. Apply the selected verbosity with set_trace_level(option.trace_level).

The relevant pattern is:

    _cmdline->parse(argc, argv);
    const OPTION& option = _cmdline->value();

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, trace_event_t event, stream_t* s) -> void {
            _logger->write(s);
        };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

For example, run a debug-built sample with -d --debug to activate debug-level events, or use -d --trace for trace-level detail. -D 0 and -D 2 select the corresponding numeric levels in the sample command-line contract. These switches are only registered in builds compiled with DEBUG; passing them to a non-debug build is not a substitute for compiling the debug configuration.

The source contains trace calls before the handler is installed, but event delivery is gated: the debug option must be present in get_trace_option(), a handler must be registered, and the category/level checks must pass. Therefore, the important workflow is to activate the existing diagnostics, not to add new log statements first.

### Event delivery and error context

trace_debug_event* routes an event to the registered handler only when the trace option is enabled and the category is not filtered. Leave-trace helpers additionally consult the configured debug level and use error_advisor to attach the symbolic error-code name; variants requesting a backtrace call trace_backtrace().

### Event activation and delivery

```text
debug build + command-line options
  └─ set_trace_debug(handler)
       ├─ set_trace_option(mask)
       └─ set_trace_level(level)

trace macro / trace_debug_event
  ├─ debug-build and option checks
  ├─ category / level filter
  ├─ attach source location and error description when applicable
  ├─ optional backtrace
  └─ registered handler ─► logger or caller
```

Compiling with `DEBUG` only enables the diagnostic macro implementations; it does not automatically enable event delivery. The option mask, category/level checks, and registered handler must also permit the event. In non-debug builds, leave-trace macros retain their control-flow role without the same diagnostic output.

## 4. Relationships

- [Global trace options](../trace.md) — option mask and backtrace/exception controls.
- [Error handling](error-handling.md) — symbolic error-code names used by leave-trace diagnostics.
- [Basic stream](../stream/basic_stream.md) — formatting of trace messages.
- [Test case](../unittest/testcase.md) — sample test executable command-line activation and logger forwarding.
- `trace.hpp/.cpp` and `trace_advisor.cpp` implement system-level event handling; the root `trace.hpp/.cpp` defines global controls. `test/testcase/io/sample.cpp` and `test/testcase/crypto/sample.cpp` show concrete debug-option setup examples.
