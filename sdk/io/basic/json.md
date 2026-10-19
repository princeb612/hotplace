## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# JSON Helper

## 1. Role

`sdk/io/basic/json.hpp` supplies two inline wrappers around Jansson: parse a JSON string with `json_open_stream()` or parse a JSON file with `json_open_file()`. The word “stream” in the first function's name refers to JSON text supplied in a character buffer; it does not consume a hotplace `stream_t`.

```text
const char* JSON text ──json_open_stream──┐
                                         ├──> Jansson json_t*
file path ─────────────json_open_file────┘
```

## 2. Model

Both helpers accept `json_t** object`, an input pointer, and an optional `suppress` flag. The text form delegates to `json_loads()`; the file form delegates to `json_load_file()`. The wrappers return hotplace `return_t` status values so callers can use the project's normal error-handling conventions while retaining Jansson's object model.

## 3. Important behavior and lifetime

- A null output pointer or null input pointer returns `errorcode_t::invalid_parameter`.
- If Jansson fails to parse the input, the wrapper returns `errorcode_t::internal_error`. With `suppress == false`, the implementation emits trace information containing the Jansson error line and message; with `suppress == true`, it skips that detailed trace path.
- On success, the resulting `json_t*` is assigned to the caller's output pointer. The caller owns the reference and must release it with `json_decref()` when finished.
- This wrapper does not introduce hotplace-owned JSON value types, schema validation, or a JSON serializer. Operations such as `json_unpack()` remain Jansson operations.

The distinction matters in code review: a caller may suppress parse diagnostics when malformed JSON is an expected test/validation outcome, but should still check the returned status before dereferencing the output pointer.

## 4. Example from the source tests

There is no dedicated `test/testcase/io/basic` JSON unit test in this source tree. The helper is exercised by real consumer code instead:

- `test/testcase/jose/testvector_akp.cpp` and `test/testcase/cose/testvector_akp.cpp` load JSON test-vector files with `json_open_file()`.
- JOSE composer code calls `json_open_stream()` to parse encoded/protected header JSON and related text.

A representative ownership sequence is: initialize `json_t* root = nullptr`, call `json_open_file(&root, filename)`, check the return value and `root`, access members using Jansson functions such as `json_unpack()`, and finally call `json_decref(root)`. The source comment in `json.hpp` documents this pattern explicitly.

## 5. Relationships

- Jansson — owns parsing, JSON value representation, unpacking, and reference counting.
- `sdk/base/system/trace.hpp` — supplies trace/error reporting used when parsing fails.
- `sdk/crypto/jose/` and `sdk/crypto/cose/` — use the helper for test vectors, keys, and JOSE header processing.

## 6. References

- Jansson API: `json_loads()`, `json_load_file()`, `json_unpack()`, and `json_decref()`.

### Source

- `sdk/io/basic/json.hpp`
- `test/testcase/jose/testvector_akp.cpp`
- `test/testcase/cose/testvector_akp.cpp`
