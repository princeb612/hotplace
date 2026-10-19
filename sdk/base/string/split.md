## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# String Split Context

## 1. Role

`split.hpp/.cpp` implements delimiter-based splitting into fragments that can be retrieved individually or visited through callbacks. The API is a context-based alternative to repeatedly writing delimiter scans at each call site.

## 2. Model

`split_context_t` owns a copy of the input in `source` and records each fragment as a `{begin, length}` pair in `info`. It does not store a separate `std::string` for every fragment at initialization; `split_get()` or callback iteration materializes fragment strings/data when requested.

```text
split_begin(source, delimiter)
        |
        v
split_context_t
  source: owned string copy
  info: vector of {begin, length}
        |
        +--> split_count()
        +--> split_get(index, binary_t|string)
        +--> split_foreach(callback)
        +--> split_chained_foreach(callback)
        |
     split_end()
```

## 3. Important behavior and lifetime

### API flow

1. `split_begin(&handle, source, delimiter)` creates the context.
2. `split_count(handle, count)` reports the fragment count.
3. `split_get(handle, index, output)` retrieves one fragment as `binary_t` or `std::string`.
4. `split_foreach()` visits each fragment; `split_chained_foreach()` expects a boolean-like callback result and stops with `internal_error` when it returns `false`.
5. `split_end(handle)` ends the context lifetime.

The callback templates check for a null context and return `invalid_parameter`. Callers should still follow the API's begin/use/end lifecycle.

## 4. Example from the source tests

### Example from the testcase

`test_string_split()` splits a colon-delimited list of TLS cipher-suite names, obtains the count, retrieves each fragment into a `binary_t`, prints each fragment, and calls `split_end()`.

The current testcase ends with `assert(true, ...)`; that assertion records execution of the case but does not independently compare the resulting fragments with an expected list. See [`testcase_string.md`](../../../test/testcase/base/string/testcase_string.md).

## 5. Relationships

- General scanning and token helpers are documented in [string.md](string.md).
- `sdk/base/stream/splitter.hpp` is a different API: it segments byte inputs into groups/segments and supports descriptor callbacks.
- The test source is `test/testcase/base/string/testcase_string.cpp`, function `test_string_split()`.

## 6. References

- API and context structure: `sdk/base/string/split.hpp`
- Implementation: `sdk/base/string/split.cpp`

### Source basis

Edition 1 · Revision 1104
