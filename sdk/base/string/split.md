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

# String Split Context

## 1. Role

`split.hpp/.cpp` implements delimiter-based splitting into fragments that can be retrieved individually or visited through callbacks. The API is a context-based alternative to repeatedly writing delimiter scans at each call site.

## 2. Data Model

`split_context_t` owns a copy of the input in `source` and records each fragment as a `{begin, length}` pair in `info`. It does not store a separate `std::string` for every fragment at initialization; `split_get()` or callback iteration materializes fragment strings/data when requested.


## 3. Behavior Model

### Context lifecycle

```text
split_begin(source, delimiter) ─► split_context_t
                                      ├─ owned source string
                                      └─ vector of {begin, length} ranges

split_count() / split_get() / split_foreach() / split_chained_foreach()
                                      │
                                      ▼
                               split_end()
```

### API flow

1. `split_begin(&handle, source, delimiter)` creates the context.
2. `split_count(handle, count)` reports the fragment count.
3. `split_get(handle, index, output)` retrieves one fragment as `binary_t` or `std::string`.
4. `split_foreach()` visits each fragment; `split_chained_foreach()` expects a boolean-like callback result and stops with `internal_error` when it returns `false`.
5. `split_end(handle)` ends the context lifetime.

### Practical example: turn a delimited list into individual values

```cpp
split_context_t* handle = nullptr;
size_t count = 0;
binary_t item;

split_begin(&handle, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", ":");
split_count(handle, count);
for (size_t i = 0; i < count; ++i) {
    split_get(handle, i, item);
    // item contains one cipher-suite name
}
split_end(handle);
```

The delimiter is removed from the returned fragments, so `count` is `2` and each `split_get()` retrieves one name. The context must be ended after use. This mirrors the lifecycle in `test_string_split()` while shortening the input to make the result easy to see.

The callback templates check for a null context and return `invalid_parameter`. Callers should still follow the API's begin/use/end lifecycle.

## 4. Relationships

- General scanning and token helpers are documented in [string.md](string.md).
- `sdk/base/stream/splitter.hpp` is a different API: it segments byte inputs into groups/segments and supports descriptor callbacks.
- The API/context is declared in `split.hpp` and implemented in `split.cpp`. The test source is `test/testcase/base/string/testcase_string.cpp`, function `test_string_split()`.

## 5. References

No external references are listed.
