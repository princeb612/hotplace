## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Revision: workspace-docs-1111                │
│ Source basis: current printf implementation  │
│ — source structure, implementation & history│
└──────────────────────────────────────────────┘
```

# Low-level printf runtime

## 1. Role

`printf.hpp` and `printf_charset.cpp` implement a callback-driven formatted-output runtime. Instead of writing directly to `stdout` or a fixed stream, the formatter emits each output fragment through a caller-supplied callback. `bufferio_charset.cpp` adapts this runtime to the low-level buffer I/O layer.

The implementation carries a 1990 Regents of the University of California, Berkeley copyright and redistribution notice. That is strong evidence of the inherited code's stated licensing provenance, but the files do not identify a specific upstream repository, release, or exact original source file. The safest history note is therefore that this is Berkeley-licensed legacy `printf` code, substantially ported and extended in hotplace—not a claim that a particular upstream snapshot has been identified.

### Maintained history visible in the source

`printf_charset.cpp` records hotplace-side changes from the 1997 port through later format and platform updates:

- 1997: porting (`hush1997`)
- 2004: `long double` formatting work (`hush2002`)
- 2009: porting (`merlin`)
- 2013: `%I64i` / `%I64u`
- 2018: `%zi` / `%zu` / `%zd`
- 2020: `%I128i` / `%I128u`
- 2021: Unicode support
- 2024: `inf`, `-inf`, `nan`, and negative zero handling
- 2026: `%%` and return-value fixes

This is the history explicitly recorded in the source, not a complete reconstruction of every change. The initial source used before the 1997 port is not identified in the current file headers.

## 2. Data Model

- `printf_context_t` carries formatter state shared with the output callback. Its current `indent` field controls indentation inserted after newline characters.
- `CALLBACK_PRINTFA` and `CALLBACK_PRINTFW` define narrow- and wide-character output sinks. Each callback receives the context, a pointer to an output fragment, and its length.
- The format string and `va_list` are consumed by the runtime; the caller remains responsible for supplying arguments of types compatible with the conversion specifiers.
- `vprintf_runtime()` is the `va_list` entry point; `printf_runtime()` is the variadic wrapper. Windows builds also expose the wide-character runtime.
- `printf_charset.cpp` uses a local conversion buffer and formatter state for flags, width, precision, sign, integer base, and floating-point conversion. Output fragments are sent through the callback rather than accumulated by the formatter itself.

## 3. Behavior Model

### Call path

```text
caller
  │ format string + variadic arguments
  ▼
printf_runtime()
  │ initializes va_list
  ▼
vprintf_runtime()
  │ scans literal text and '%' conversion directives
  │ parses flags, width, precision, and length modifiers
  │ converts the selected argument into an output fragment
  ▼
runtime_printf(context, fragment, length)
  │
  ▼
caller-owned destination

bufferio::printf/vprintf
  └─ callback adapter → vprintf_runtime() → buffer output
```

1. The runtime validates the callback and format-string pointers, then scans the format string until a conversion marker, newline, or terminator.
2. Literal runs are emitted directly. A newline is emitted and, when `context->indent` is nonzero, the runtime emits the configured number of spaces afterward.
3. For a conversion directive, the runtime parses flags, field width, precision, and length modifiers, reads the corresponding variadic argument, and formats it into a fragment.
4. The fragment is passed to the callback. The callback determines the destination and its storage policy; the formatter does not own that destination.
5. The runtime tracks the number of output characters for its return value. Callers should check the implementation's return/error conventions rather than assuming they exactly match every platform's standard `printf`.

### Compatibility boundaries

- The implementation includes platform-oriented extensions such as `%I64...` and `%I128...`, plus `%z` length modifiers and wide-character entry points. These extensions mean the supported format language should not be described as identical across all C libraries or platforms.
- Floating-point conversion is implemented locally and uses `ieee754.hpp` to classify values and preserve the sign of negative zero. The source explicitly marks `long double` as unimplemented in its format flags despite an older history entry mentioning long-double work; this discrepancy should be resolved from tests or history before documenting `long double` as supported.
- The newline path has an additional indentation behavior, so format strings containing newlines can produce output different from a plain C `printf` call.
- Like other variadic formatters, this API depends on the format string matching the actual argument types. A mismatch can cause undefined behavior; untrusted format strings should not be passed with unrelated arguments.

### Existing usage example

`test_string_printf()` in `test/testcase/base/string/testcase_string.cpp` passes `"%s %i %1.1f"` and a callback that appends each emitted fragment to `context.str`. The testcase currently prints the result but asserts unconditionally, so it demonstrates the call path rather than verifying the exact formatted output. A focused regression test should compare the result with `"sample 1 1.1"` and cover the maintained extensions and edge cases.

## 5. Relationships

- `printf.hpp` — callback types, context, and public runtime declarations.
- `printf_charset.cpp` — format scanning and conversion implementation.
- `bufferio_charset.cpp` — integration with the low-level buffer I/O abstraction.
- `printf_wcs.cpp` under `sdk/base/stream/unicode/` — wide-character build path that includes the shared formatter implementation.
- `test/testcase/base/string/testcase_string.cpp` — direct callback-based usage.
- `sdk/base/stream.md` — higher-level stream interface; this low-level runtime is a separate callback-based formatter, not the same API as the indexed `sprintf()`/`valist` path shown there.

## 6. References

- Source license and copyright notice in `sdk/base/stream/lowlevel/printf.hpp` and `printf_charset.cpp`: Regents of the University of California, Berkeley, copyright 1990.
- No exact upstream repository, release tag, or original source URL is identified in the current source headers.