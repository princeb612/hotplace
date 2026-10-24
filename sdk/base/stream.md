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

# Stream interface

## 1. Role

The root-level `stream.hpp` declares the abstract `stream_t` interface shared by stream-like implementations. It defines the common operations without choosing a concrete storage backend.

## 2. Data Model

- `stream_type_t` identifies undefined, memory, and file stream categories.
- `stream_t` is an abstract base with a virtual destructor.
- The interface exposes byte data and size, write/fill/clear operations, empty/occupied state, formatted output via `printf`/ `vprintf`, automatic indentation, and resize.

The interface returns `return_t` for operations that can fail, while state queries return values directly. Concrete subclasses determine the ownership of `data()`, how capacity differs from logical size, and what resize means.

## 3. Behavior Model

**Storage and mutation methods**

`write()`, `fill()`, `clear()`, and `resize()` define the mutation surface. The base class supplies no storage implementation, allocation policy, or pointer-stability guarantee.

**Formatted output**

`printf()` and `vprintf()` provide variadic and `va_list` formatting entry points. Concrete classes define whether the result is textual, binary, or otherwise constrained.

**State and accessors**

`data()`, `size()`, `empty()`, and `occupied()` expose the concrete stream's current state. Callers should consult the specific implementation before retaining a data pointer across writes or resize operations.

### Concrete consumer path: format into an abstract stream

The formatting API accepts the abstract `stream_t*`, allowing the caller to choose a concrete destination while keeping the formatting call unchanged:

```cpp
basic_stream output;
valist args;
args << 3.141592 << "phi" << 123;

sprintf(&output, "value={1} value={2} value={3}", args);
// output: value=3.141592 value=phi value=123
```

This is the pattern used by the `valist` testcase: `basic_stream` supplies the destination implementation, while `sprintf()` consumes indexed arguments and writes formatted text through the stream interface. The base `stream_t` contract does not promise that every concrete stream has identical storage or pointer-stability behavior.

Source: `test/testcase/base/basic/testcase_valist.cpp`.

## 4. Relationships

- `sdk/base/stream.hpp` declares the abstract contract; `sdk/base/stream/` supplies concrete in-memory streams and low-level buffers.
- `sdk/io/stream/` — stream adapters that interact with external I/O.
- `sdk/base/basic/valist.md` — formatting argument representation used by stream formatting paths.

## 5. References

No external references are listed.
