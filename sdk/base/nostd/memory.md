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

`memory.hpp` provides C++11-compatible helpers for creating uniquely owned objects and arrays, attaching custom deleters, and temporarily managing raw pointers. These facilities are implementation tools; their presence does not establish one ownership policy for all hotplace components.

## 2. Data Model

The `custom` namespace defines:

- `make_unique<T>(args...)` — allocate one object and return a `std::unique_ptr<T>`.
- `make_unique<T[]>(size)` — value-initialize an array and return an owning array pointer.
- `make_unique_with_deleter<T>(deleter, args...)` — create an object with a caller-supplied deleter.
- `make_unique_with_deleter<T[]>(size, deleter)` — create an array with a caller-supplied deleter.
- `make_promise_on_destruction(ptr, deleter)` — adopt an existing raw pointer into a `unique_ptr` with the supplied release operation.

The header also defines `t_pointer_proxy<T>`, a small RAII wrapper for a raw pointer and a configurable deletion callback.

## 3. Behavior Model

**Allocation and pointer adoption**

The `make_unique` helpers allocate the requested object or array and return unique ownership through `std::unique_ptr`. The custom-deleter overloads preserve the supplied deleter type, supporting resources whose release operation is not plain `delete`.

`make_promise_on_destruction()` does not allocate the object. It wraps a pointer already obtained from another API, and invokes the supplied deleter when the returned owner is destroyed unless ownership has been released through the standard smart-pointer interface.

For `std::unique_ptr`, `release()` returns the raw pointer and relinquishes ownership without invoking the deleter. Destruction invokes the deleter only while the `unique_ptr` still owns the pointer. This standard-library behavior should not be conflated with the project-defined `t_pointer_proxy<T>::release()`, which returns `void` and clears the proxy's stored pointer.

**Temporary pointer proxy**

`t_pointer_proxy` invokes its configured deleter on destruction while it retains the pointer. Its `release()` operation clears the stored pointer so the proxy will no longer delete it. The exact transfer sequence depends on the caller and receiving API; this helper does not impose a project-wide ownership convention.

### Exploratory low-memory ownership direction

The source contains an experimental investigation of a low-memory-oriented ownership-transfer path for `payload_member`:

```cpp
payload& operator<<(std::unique_ptr<payload_member> member);
payload& operator<<(t_pointer_proxy<payload_member> proxy);
```

These overloads record that both a standard unique-owner input and the project pointer-proxy input were considered/accepted at this particular transfer boundary. The investigation was intended as a possible low-memory mitigation direction.

This is a localized experimental trace, not a generalized hotplace ownership policy, not evidence that the approach was adopted across projects, and not a recommendation to prefer either interface universally. Treat it as historical design exploration unless a component-specific implementation and contract establish otherwise.

### Concrete caller path: release a reference-counted protocol object

The network stream uses `make_promise_on_destruction()` to adapt a raw pointer returned by protocol selection into a scope-bound owner:

```cpp
network_protocol* protocol = nullptr;
test = protocol_group->is_kind_of(
    bufstream.data(), bufstream.size(), &protocol);

if (errorcode_t::success == test) {
    auto lambda_deleter = [](network_protocol* object) -> void {
        object->release();
    };
    auto protocol_ptr =
        custom::make_promise_on_destruction<network_protocol>(
            protocol, lambda_deleter);

    protocol_ptr.get()->read_stream(
        &bufstream, &message_size, &state, &priority);
}
```

The raw pointer is returned by the protocol-selection path with its reference count incremented. The custom deleter calls `release()` when the local smart pointer leaves scope, including early exits from the surrounding processing path. This is a concrete caller-specific adaptation, not a universal ownership recipe.

Source: `sdk/net/server/network_stream.cpp`, `network_stream::do_writep()`.

## 4. Relationships

- `sdk/base/nostd/utility.md` — other conversion and generic helper functions.
- `sdk/net/server/network_stream.cpp` — uses `make_promise_on_destruction` to ensure a reference-counted `network_protocol` is released when temporary processing finishes.
- C++11 compatibility — these helpers should not be mistaken for a new language-standard requirement.

## 5. References

- [cppreference: std::make_unique](https://en.cppreference.com/w/cpp/memory/unique_ptr/make_unique) — C++14 standard-library API used as a comparison point for the C++11-compatible helper.
