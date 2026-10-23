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

# Exception utility

## 1. Role

`exception.hpp` and `exception.cpp` define hotplace's project exception abstraction and error-code integration. The type is used by low-level utilities to report exceptional conditions, including size/range constraints in utility classes.

## 2. Data Model

The `exception` object stores an `errorcode_t` and an optional caller-provided description string. It does not derive from `std::exception`; APIs that return `return_t` use a separate result representation rather than storing it in this object.

## 3. Behavior Model

### Error propagation boundary

```text
operation detects error
        ├─ return-code API ─► return_t ─► caller checks result
        └─ exception path ─► exception ─► caller catches or propagates
```

Do not infer that every API throws: the call site determines which contract applies.

### Access and propagation

`get_errorcode()` returns the stored code, `get_description()` returns the caller-supplied description, and `get_error_message()` asks `error_advisor` to map the code to a human-readable message.

Copy/move operations preserve the error code and copy or move the description. Throwing the object is a caller decision; this utility does not force callers to use exceptions.

## 4. Relationships

- `sdk/base/nostd/bit_set.hpp` — throws this exception for oversized storage allocation.
- `sdk/base/system/error.hpp` — supplies error-advisor message lookup for exception diagnostics. The implementation is in `exception.hpp/.cpp`, and `testcase_exception.cpp` covers the exception behavior.
