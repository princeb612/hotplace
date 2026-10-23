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

## 4. Relationships

- `sdk/base/error.hpp` — shared error-code values used for allocation failure.
- `sdk/base/stream.hpp` and `sdk/base/types.hpp` — foundational includes.
- The source tree uses these macros in many components; inspect the call site to determine cleanup and error propagation.
