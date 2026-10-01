# multiplexer

The multiplexer layer abstracts platform event notification for asynchronous I/O.

## Architecture

```text
higher-level I/O / network
          |
          v
     multiplexer
          |
   +------+------+ 
   |             |
 epoll          IOCP
 Linux         Windows
```

`multiplexer_controller` provides the control path while platform implementations provide the actual event mechanism.

## Implemented backends

- Linux: `multiplexer_epoll.cpp`
- Windows: `multiplexer_iocp.cpp`

The source declares the broader multiplexer abstraction, but this revision should not be read as claiming a complete `kqueue` backend; the relevant enum/declarations do not represent an implemented backend.

## Related source

- `sdk/io/system/multiplexer.hpp`
- `sdk/io/system/multiplexer_controller.cpp`
- `sdk/io/system/multiplexer_epoll.cpp`
- `sdk/io/system/multiplexer_iocp.cpp`

## Related area

`sdk/net/server/` consumes the multiplexer layer as part of the server/session flow.
