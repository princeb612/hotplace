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

# Control-flow and allocation macros

## 1. Role

`syntax.hpp` defines project macros for single-exit cleanup flow and allocation-failure handling. These are source-level conventions used throughout hotplace, not C++ language constructs.

## 2. Data Model

- `__trynew` and `__catchnew` map to C++ exception syntax in C++ builds.
- `__try_new_catch*` macros combine allocation with an error-result convention.

The macro names resemble structured exception handling, but `__finally2` is not a language-level `finally` block and does not automatically execute cleanup after an arbitrary C++ exception.

## 3. Behavior Model

**Single-exit flow**

`__try2`, `__finally2`, and `__leave2` form a `do { ... } while (0)` block with `break` as the early-exit mechanism.

Code between `__try2` and `__finally2` is expanded into a single-iteration loop. `__leave2` exits that loop with `break`; the trailing `__finally2` expansion closes the loop. Any cleanup in the trailing block runs only if normal control flow reaches it.

**Allocation wrappers**

`__try_new_catch*` macros assign a newly created pointer and set an error result or leave the block when allocation fails. `__try_new_catch` defaults the failure result to `errorcode_t::out_of_memory`. `__try_new_catch2` allows a caller-selected error code. The `leave` argument controls what the caller does after a failed allocation, typically leaving the surrounding single-exit block.

**Exception boundary**

In C++, the allocation macros catch `std::bad_alloc`; they do not catch arbitrary exceptions. Their behavior depends on the exact macro combination and the caller's assignment/leave statements.

### Concrete caller path: early exit with cleanup

The TLS certificate loader uses the macros to validate inputs, stop after a failed operation, and keep one return path:

```cpp
return_t ret = errorcode_t::success;
__try2 {
    if (nullptr == certfile || nullptr == keyfile) {
        ret = errorcode_t::invalid_parameter;
        __leave2;
    }

    ret = keychain.load_file(&temp, key_certfile, certfile,
                             keydesc(KID_TLS_SERVER_CERTIFICATE_PUBLIC));
    if (errorcode_t::success != ret) {
        __leave2;
    }

    // Load the private key and register the loaded key objects.
}
__finally2 {}
return ret;
```

This abbreviated path illustrates the control-flow convention: `__leave2` exits the single-iteration block, after which the function reaches `return ret`. The empty `__finally2 {}` does not perform cleanup by itself. A non-empty trailing block can run cleanup only when control reaches it normally; these macros are not C++ `finally` semantics and should not be treated as an exception-safe resource guard.

Source: `sdk/net/tls/sdk.cpp`, `load_certificate()`.

## 5. Relationships

- `sdk/base/error.hpp` — shared error-code values used for allocation failure.
- `sdk/base/stream.hpp` and `sdk/base/types.hpp` — foundational includes.
- The source tree uses these macros in many components; inspect the call site to determine cleanup and error propagation.

## 6. References

No external references are listed.
