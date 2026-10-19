## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# socket

## 1. Role

`socket.hpp` / `socket.cpp` provides the low-level socket wrapper used by the I/O and network layers.

It centralizes platform socket operations so higher layers do not need to directly mix POSIX and Winsock calls.

```text
network socket abstraction
          |
     sdk/io/system/socket
        /          \
     POSIX       Winsock
```

The related `winsock.cpp` and platform support files provide the Windows-specific side of the abstraction.

## 2. Model

The existing implementation notes are retained below; see the references for the concrete source files.

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

No dedicated source-test example was documented in the existing notes. See the linked test sources, where present.

## 5. Relationships

### Relationship

The low-level socket layer is below `sdk/net/basic/`, where client/server socket abstractions add transport, TLS and role-specific behavior.

## 6. References

### Related source

- `sdk/io/system/socket.hpp`
- `sdk/io/system/socket.cpp`
- `sdk/io/system/winsock.cpp`
- `sdk/io/system/types.hpp`
