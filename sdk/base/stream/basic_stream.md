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

# `basic_stream`

## 1. Role

`basic_stream` is hotplace's mutable in-memory stream for assembling text and formatted output. It extends `stream_t` and exposes stream editing and formatting operations to SDK code. It is a base utility, not an OS file stream or a protocol-specific encoder.

## 2. Data Model

The class combines buffer editing (`insert()`, `cut()`), formatted output (`printf()`, `println()`, `vprintf()` and hotplace's `vaprintf()` family), and stream composition through insertion/append operators and encoder-stream traits. `stream_policy` and `local_stream_policy` control allocation behavior.

```text
SDK caller / formatting helper
              |
              v
        basic_stream
     +-- append / operators
     +-- insert / cut
     +-- printf / println / vaprintf
              |
              v
           stream_t
              |
              v
       in-memory buffer
```

This is a logical relationship diagram; `basic_stream` does not represent an OS handle.

## 3. Behavior Model

- Narrow and wide formatted-output entry points are provided.
- `vaprintf()` uses hotplace's argument/value formatting model; its format syntax is not identical to standard C `printf` in every respect. The testcase exercises positional fields with hexadecimal width/zero padding, string alignment, and floating-point formatting, expecting `value=0x0100`, a padded `hello world`, and `3.141592e+00`.
- The stream can be edited after writing, so append-only assumptions should not be made when using insertion or cutting operations.
- Allocation policy is part of the stream configuration, not a separate stream format.

## 4. Relationships

- `stream_t` — base abstraction inherited by `basic_stream`.
- `stream_policy.hpp` — allocation policy types; `basic_stream.hpp` contains the concrete stream interface and implementation hooks.
- `lowlevel/` — lower-level buffered output and formatting implementation.
- `string-stream.md` — string-oriented stream classes; related, but not the same abstraction.
- `sdk/io/stream/` — OS/file-oriented stream adapters.
- `test/testcase/base/stream/testcase_stream.cpp` — [testcase notes](../../../test/testcase/base/stream/testcase_stream.md) — see `test_stream_basic_stream()` for formatting and append behavior, `t_test_rule_of_5<basic_stream>()` for object-lifetime semantics, and `test_stream_i128()` for integer-formatting examples. These tests illustrate exercised behavior; this document does not assert that they were executed in a particular environment.
