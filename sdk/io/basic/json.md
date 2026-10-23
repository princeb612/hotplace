## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
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
file path ─────────────json_open_file─────┘
```

## 2. Data Model

### Inputs, output slot, and status

Both wrappers accept an output slot `json_t** object`, an input pointer, and an optional `suppress` flag. The input is either a NUL-terminated JSON text buffer for `json_open_stream()` or a file path for `json_open_file()`. Despite its name, `json_open_stream()` does not consume hotplace's `stream_t`.

The wrapper's return type is hotplace `return_t`; the parsed value is Jansson's `json_t*`. These are separate outputs with separate responsibilities: the status reports whether the wrapper completed successfully, while the pointer identifies the parsed JSON tree.

### Jansson value and ownership

The parsed object remains a Jansson value tree. The wrapper does not translate it into a hotplace-owned JSON model or perform schema validation. Jansson functions such as `json_unpack()` operate on the returned tree.

A successful parse produces a reference that the caller must release with `json_decref()`. The output pointer is an output slot; the wrapper does not release a pre-existing object stored there before assigning the newly parsed root.

### Error context

When parsing fails, Jansson provides a `json_error_t` containing details such as the line and message. The `suppress` flag controls whether the wrapper emits trace information for that parse failure; it does not turn a failed parse into success or change the return status.

## 3. Behavior Model

### Parse JSON text

```text
json_open_stream(&root, buffer, suppress)
          │
          ├─ object == nullptr OR buffer == nullptr
          │      └─ invalid_parameter
          ▼
      json_loads(buffer, 0, &jerror)
          │
          ├─ root == nullptr
          │      ├─ suppress == false ─► trace line + Jansson error text
          │      └─ suppress == true  ─► skip detailed trace
          │      └─ return internal_error
          ▼
      *object = root
          │
          ▼
      return success
          │
          ▼
caller uses Jansson API, then json_decref(root)
```

### Parse a JSON file

```text
json_open_file(&root, file, suppress)
          │
          ├─ object == nullptr OR file == nullptr
          │      └─ invalid_parameter
          ▼
    json_load_file(file, 0, &jerror)
          │
          ├─ parse / file-read failure
          │      ├─ suppress == false ─► trace line + error text
          │      └─ suppress == true  ─► skip detailed trace
          │      └─ return internal_error
          ▼
    *object = root ─► caller's Jansson operations ─► json_decref(root)
```

The wrappers assign the output pointer only after Jansson returns a non-null root. Callers must check the returned status before dereferencing the result, and must release a successfully returned reference when finished. If the caller reuses an output slot that already owns a Jansson reference, it must manage that old reference separately before calling the wrapper.

### Source-level usage boundary

No dedicated JSON testcase is present under `test/testcase/io/basic`. The helper is used by JOSE/COSE test-vector loaders and JOSE header-processing code. Those consumers demonstrate integration and ownership patterns, but they are not a dedicated assertion suite for every invalid-parameter, parse-error, or suppression branch.

## 4. Relationships
- Jansson — owns parsing, JSON value representation, unpacking, and reference counting.
- `sdk/base/system/trace.hpp` — supplies trace/error reporting used when parsing fails.
- `sdk/crypto/jose/` and `sdk/crypto/cose/` — use the helper for test vectors, keys, and JOSE header processing.

### Implementation source navigation

- `sdk/io/basic/json.hpp`

## 5. References
- [Jansson API reference](https://jansson.readthedocs.io/en/latest/apiref.html) — JSON loading, unpacking, and reference-counted value management.