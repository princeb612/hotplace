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

# Exception utility

## 1. Role

`exception.hpp` and `exception.cpp` define hotplace's project exception abstraction and error-code integration. The type is used by low-level utilities to report exceptional conditions, including size/range constraints in utility classes.

## 2. Data Model

```text
operation detects error
        |
        v
hotplace error code / exception
        |
        v
caller handles or propagates it
```

Do not infer that every API throws: several utility methods return `return_t` error codes, while other paths explicitly construct or throw `exception` objects. The call site determines which contract applies.

## 3. Behavior Model

### Stored error and message

The exception stores an errorcode_t and an optional description string. get_errorcode() returns the code, get_description() returns the caller-supplied description, and get_error_message() asks error_advisor to map the code to a human-readable message.

This class does not derive from std::exception and does not expose a what() method. Catching it therefore requires the project exception type (or an appropriate catch-all), not a std::exception reference.

Copy/move operations preserve the error code and copy or move the description. Throwing the object is a caller decision; APIs that return return_t remain a separate error path.

## 4. Relationships

- `sdk/base/nostd/bit_set.hpp` — throws this exception for oversized storage allocation.
- `sdk/base/system/error.hpp` — supplies error-advisor message lookup for exception diagnostics. The implementation is in `exception.hpp/.cpp`, and `testcase_exception.cpp` covers the exception behavior.
