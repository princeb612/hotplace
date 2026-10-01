# socket

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

## Related source

- `sdk/io/system/socket.hpp`
- `sdk/io/system/socket.cpp`
- `sdk/io/system/winsock.cpp`
- `sdk/io/system/types.hpp`

## Relationship

The low-level socket layer is below `sdk/net/basic/`, where client/server socket abstractions add transport, TLS and role-specific behavior.
