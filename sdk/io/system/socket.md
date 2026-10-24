## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — socket creation, readiness and ownership   │
└──────────────────────────────────────────────┘
```

# Socket utilities

## 1. Role

`socket.hpp/.cpp` provides low-level socket creation, connection, waiting, nonblocking-mode, address conversion, and shutdown helpers. It keeps POSIX and Winsock calls out of most callers, but it does not create the higher-level client/server or TLS session abstractions in `sdk/net/basic/`.

## 2. Data Model

| API | Inputs and output | What the caller should understand |
|---|---|---|
| `create_socket` | socket type, address, port; returns socket and resolved address | Selects IPv4/IPv6/hostname handling and creates a stream or datagram socket |
| `create_listener` | array of address families, output socket array, protocol and port | Supports creating listener sockets for requested families; the caller owns every successfully created socket |
| `connect_socket` | address, port and timeout in seconds | Creates and connects a socket through the address-based helper path |
| `connect_socket_addr` | existing socket and sockaddr | Connects to a prebuilt native address |
| `wait_socket` | socket, timeout in milliseconds, readable/writable flags | Waits for readiness; this is distinct from multiplexer callback dispatch |
| `set_sock_nbio` | socket and nonblocking mode | Changes the socket's blocking mode |
| `close_socket` | socket, shutdown flag and linger value | Closes/releases the OS resource with the requested shutdown/linger behavior |
| `addr_to_sockaddr` / `sockaddr_string` | address representation | Converts between text address and native storage |
| `typeof_socket` | socket; output type | Reports stream/datagram type, used by the multiplexer to classify events |

The Windows build additionally exposes `winsock_startup()` and `winsock_cleanup()`. `socket_advisor` maps address-family, socket-type and protocol numeric values to names for diagnostics; it is not a socket lifecycle manager.

## 3. Behavior Model

### How address input is interpreted

`create_socket` uses the address text to choose the resolver hints: strings that look like numeric IPv4/IPv6 addresses use `AI_NUMERICHOST`; hostnames use `AI_PASSIVE`. It requests `AF_UNSPEC`, then attempts supported IPv4/IPv6 results. Stream sockets use TCP and datagram sockets use UDP as their protocol hint. Callers should not assume that a hostname is resolved the same way as a numeric literal or that every candidate address will yield a socket.

### Readiness and nonblocking I/O

`wait_socket` is a utility for waiting on readability/writability with a millisecond timeout. The multiplexer is a separate abstraction: epoll reports readiness to its callback, while IOCP reports completion of a submitted overlapped operation. A caller must not treat `wait_socket` readiness as a completed transfer or as a substitute for handling partial reads/writes.

### Resource ownership

Sockets are native resources. Every successful create/connect/listener path must be paired with the appropriate close path, and a socket must not be closed while another thread or callback can still use it. For listeners, the caller owns each socket in the output vector. On Windows, overlapped sockets and Winsock startup/cleanup must be coordinated with the lifetime of the code using them. A minimal caller flow is to initialize the socket to `INVALID_SOCKET`, call `create_socket()` with an output `sockaddr_storage_t`, use the successfully created socket, and finish with `close_socket()`; the exact cleanup path must account for failures and platform-specific startup requirements.

### Concrete consumer path: TCP client connection

The naive TCP client calls `create_socket()` to resolve the address and create the native socket, then passes the resulting socket and resolved address to `connect_socket_addr()`:

```cpp
#include <hotplace/sdk/io/system/socket.hpp>

// Reduced from sdk/net/basic/naive/naive_tcp_client_socket.cpp
auto type = socket_type();
sockaddr_storage_t address_info;
ret = create_socket(&_fd, &address_info, type, address, port);
if (errorcode_t::success == ret) {
    ret = connect_socket_addr(
        _fd, (sockaddr*)&address_info, sizeof(address_info), timeout);
}
```

The two calls have different responsibilities: socket creation/resolution does not complete the connection. The owning client class later closes the socket and resets its handle to `INVALID_SOCKET`; callers using the low-level functions directly must provide equivalent cleanup on both success and failure paths.

Source: `sdk/net/basic/naive/naive_tcp_client_socket.cpp`, `naive_tcp_client_socket::connect()` and `close()`.

## 4. Relationships
- [Event multiplexer](multiplexer.md) — classifies sockets and dispatches readiness/completion callbacks.
- `sdk/net/basic/` — adds client/server role, transport and secure-backend behavior.
- `sdk/net/server/` — consumes sockets with the event multiplexer.

### Implementation source navigation

- `sdk/io/system/socket.hpp`
- `sdk/io/system/socket.cpp`
- `sdk/io/system/winsock.cpp`
- `sdk/io/system/types.hpp`
- `sdk/net/basic/`

## 5. References
- [Linux man-pages: socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html), [connect(2)](https://man7.org/linux/man-pages/man2/connect.2.html), [shutdown(2)](https://man7.org/linux/man-pages/man2/shutdown.2.html), and [getaddrinfo(3)](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) — POSIX socket and address-resolution APIs.
- [Microsoft Learn: Winsock functions](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-functions) — Windows socket API, including WSASocket and ioctlsocket.