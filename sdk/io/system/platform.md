# platform

The remaining files in `sdk/io/system` provide platform-specific support around the common I/O primitives.

```text
                 sdk/io/system
                       |
          +------------+------------+
          |                         |
       common                  platform code
          |                         |
 socket / multiplexer       Linux / Windows APIs
```

Representative platform files include:

- Linux epoll and netlink support
- Windows IOCP and Winsock support
- Windows Registry support
- PE/Windows native structures

The directory therefore acts as a boundary: portable SDK abstractions are kept above direct operating-system APIs, while platform code remains localized here.

## Related source

- `sdk/io/system/linux/`
- `sdk/io/system/windows/`
- `sdk/io/system/multiplexer.hpp`
- `sdk/io/system/socket.hpp`
