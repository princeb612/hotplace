## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Scope: runnable TCP server applet
```

# Multiplexer-integrated TCP server applet

## 1. Role

`tcpserver1` is the low-level TCP server example in the applet progression `tcpserver1 → tcpserver2 → tlsserver → httpserver1 → httpserver2`. It demonstrates accepting stream connections and dispatching socket readiness through the platform multiplexer directly, before the higher-level `network_server` wrapper is introduced.

This is a transport/event-loop example, not an HTTP or TLS server. Its implementation contains platform-specific paths for Linux epoll and Windows IOCP.

## 2. Model

### Connection and event flow

```text
listen socket
    │ mux_connect / accept()
    ▼
client socket + netsocket_event_t
    │ bind to multiplexer
    ▼
read readiness / completion
    │
    ├── receive bytes
    ├── log the peer and payload
    └── send bytes back to the same client
    │
    ▼
disconnect → unbind → close socket → release event context
```

The per-client `netsocket_event_t` stores the client socket and peer address; on Windows it also carries the overlapped read buffer. The Linux path uses epoll readiness and explicit socket reads/writes. The Windows path issues asynchronous receive operations and handles completion through IOCP.

## 3. Important behavior and lifetime

- The accept path allocates one event context per accepted client and binds that context to the multiplexer.
- The disconnect path unbinds the socket, closes it using the platform-appropriate function, and deletes the associated context. This ownership pairing is important: the context must remain valid while the multiplexer can deliver events for that client.
- The applet uses a `.run` marker to control its run loop; the stop instructions remove the marker rather than signaling an HTTP/TLS protocol shutdown.
- A successful TCP accept only proves that a transport connection was accepted. It does not test TLS negotiation, HTTP parsing, or application protocol correctness.

## 4. Example from the source

Follow `run_server.cpp` from `accept_thread_routine` / the Linux `mux_connect` branch to `client_connected_handler`. The accepted socket receives a `netsocket_event_t`, is bound to the multiplexer, and then reaches the read path. Received data is logged and echoed to the same socket. On disconnect, the context is unbound and freed.

This example is useful when investigating event registration, platform-specific I/O, and per-connection context lifetime. It is not a deterministic unit test; the applet requires a client connection to exercise the data path.

## 5. Relationships

- [TCP server through network_server](../tcpserver2/README.md) — higher-level event/session wrapper and peer ACL.
- [TLS server](../tlsserver/README.md) — secure stream transport on top of the server path.
- [HTTP/1.1 server](../httpserver1/README.md) and [HTTP/2 server](../httpserver2/README.md) — application-protocol examples.
- [Network server implementation](../../../sdk/net/server/README.md) — session/event abstractions.

## 6. References

- `run_server.cpp` — accept, multiplexer, receive/echo, disconnect and cleanup.
- `sample.cpp`, `sample.hpp` — shared applet setup and command-line configuration.
- `CMakeLists.txt` — executable target.
- The source comments explicitly identify the intended progression to `tcpserver2`, `tlsserver`, `httpserver1`, and `httpserver2`.

## 7. Developer Notes

The applet contains distinct Linux and Windows event paths. When modifying one path, do not assume the other follows automatically; verify accept, receive, disconnect and context cleanup behavior on the relevant platform. No new runtime test was performed as part of this documentation change.
