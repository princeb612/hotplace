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

# Memory ownership helpers

## 1. Role

`memory.hpp` provides C++11-compatible ownership helpers for objects and arrays, custom deleters, and temporary raw pointers that must remain exception-safe while an object is transferred into another owner.

## 2. Data Model

The `custom` namespace defines:

- `make_unique<T>(args...)` — allocate one object and return a `std::unique_ptr<T>`.
- `make_unique<T[]>(size)` — value-initialize an array and return an owning array pointer.
- `make_unique_with_deleter<T>(deleter, args...)` — create an object with a caller-supplied deleter.
- `make_unique_with_deleter<T[]>(size, deleter)` — create an array with a caller-supplied deleter.
- `make_promise_on_destruction(ptr, deleter)` — adopt an existing raw pointer into a `unique_ptr` with the supplied release operation.

The header also defines `t_pointer_proxy<T>`, a small RAII wrapper for a raw pointer and a configurable deletion callback.

## 3. Behavior Model

**Allocation helpers**

The `make_unique` helpers allocate the requested object/array and return ownership through `std::unique_ptr`. This fills a practical gap for C++11 code that cannot rely on the C++14 standard `std::make_unique` API.

**Custom deletion**

The custom-deleter overloads preserve the supplied deleter type in the returned `unique_ptr`. This supports resources whose release operation is not plain `delete`, such as reference-counted objects that require `release()`.

**Adopting an existing pointer**

`make_promise_on_destruction()` does not allocate the object; it wraps the pointer already received from another API. The deleter runs when the returned owner is destroyed, unless ownership is released through the smart-pointer interface.

**Temporary pointer proxy**

`t_pointer_proxy` invokes its deleter on destruction. `release()` clears the stored pointer to prevent deletion after ownership has been transferred. The caller must explicitly release the proxy when another object has accepted responsibility for the pointer; otherwise the proxy remains the owner.

## 4. Relationships

- `sdk/base/nostd/utility.md` — other conversion and generic helper functions.
- `sdk/net/server/network_stream.cpp` — uses `make_promise_on_destruction` to ensure a reference-counted `network_protocol` is released when temporary processing finishes.
- C++11 compatibility — these helpers should not be mistaken for a new language-standard requirement.
## 5. References

- C++14 `std::make_unique` standard-library API
