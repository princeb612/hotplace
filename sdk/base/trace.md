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

# Global trace controls

## 1. Role

The root-level `trace.hpp/.cpp` defines trace categories/events and global option switches. It is a control surface for optional backtrace and exception tracing, distinct from `sdk/base/system/trace.hpp`, which owns trace output and category-aware event handling.

## 2. Data Model

- `trace_category_t` groups event IDs into internal, crypto, and network ranges.
- `trace_event_t` names events such as socket/multiplexer activity, cryptographic operations, TLS/QUIC records and frames, and HPACK/QPACK behavior.
- `trace_option_t` defines the option values for backtrace, exception tracing, and trace/debug output.
- The implementation stores the active option mask in a file-local `_trace_option`.

The category/event enumeration is a shared vocabulary. Defining an event ID does not itself emit an event. The declarations use `uint32` from `sdk/base/types.hpp` without including that header directly, so standalone inclusion depends on the caller's include order; the normal base include path brings the shared types in first.

## 3. Behavior Model

**`set_trace_option(option)`**

Replaces the global option value and returns the previous value. When the exception-tracing bit transitions on or off, it calls `set_trace_exception()` or `reset_trace_exception()` to synchronize the exception hook state.

**`get_trace_option()`**

Returns the current option value without changing it.

**`trace_backtrace(errorcode)`**

Declared by this header; its implementation is provided by the trace/system support layer. It should be treated as a request to report a backtrace for an error, not as a trace-event dispatcher.

**`set_trace_exception()` / `reset_trace_exception()`**

Control exception-tracing behavior through the implementation in the system trace layer. The root wrapper only coordinates these hooks when the option mask changes.

The option storage is a plain static integer rather than an atomic or locked value. Callers changing trace options concurrently should provide their own synchronization.

## 5. Relationships

- `sdk/base/system/trace.hpp/.cpp` — trace advisor/output implementation and platform backtrace integration.
- `sdk/base/types.hpp` — common integer aliases used by event and option enums.
- Higher-level crypto/network modules — consume event IDs when emitting diagnostic information.

## 6. References

No external references are listed.
