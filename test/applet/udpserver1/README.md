## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Scope: runnable UDP server applet
```

# Multiplexer-integrated UDP server applet

## 1. Role

`udpserver1` is the low-level UDP echo-server example. It registers a UDP socket with the platform multiplexer and handles datagram events directly, before the higher-level `network_server` path shown in `udpserver2`.

The source explicitly marks this applet as IPv4-only. It is a datagram/event-loop example, not a DTLS implementation.

## 2. Model

### Datagram flow

```text
IPv4 UDP socket
    │ mux_dgram
    ▼
consumer_routine
    ├── recvfrom(socket, buffer, peer address)
    ├── log peer address and datagram
    └── sendto(socket, same bytes, same peer address)
    │
    ▼
client receives echoed datagram
```

On Linux, the callback uses `recvfrom` and `sendto` explicitly. On Windows, the applet stores peer-address and overlapped-buffer state, uses `WSARecvFrom`, and sends the completed datagram back to the captured peer address.

## 3. Important behavior and lifetime

- The receive buffer is sized for a large datagram (the source defines `BUFSIZE` as `1 << 16`); the actual received byte count determines what is logged and echoed.
- The sender address returned by the receive operation is used for the response, preserving the datagram destination instead of treating the socket as a connected byte stream.
- The source creates a `.run` marker and breaks the multiplexer loop during shutdown.
- The direct implementation uses different mechanics on Linux and Windows: readiness plus `recvfrom` on Linux, overlapped receive/completion state on Windows.

UDP preserves datagram boundaries but does not provide TCP-style delivery, ordering or retransmission guarantees. A successful echo for one packet does not verify loss, duplication, truncation, packet-size limits or behavior under concurrent senders.

## 4. Example from the source

Send one UDP datagram to the configured IPv4 port. The event callback receives the socket event, reads the datagram and peer address, logs the bytes, then sends the same bytes back to that peer. The relevant code path is `udp_server` → multiplexer event loop → `consumer_routine(mux_dgram)`.

The source and build determine the executable name and port defaults. This documentation update did not run a live UDP client/server test.

## 5. Relationships

- [Network-server UDP example](../udpserver2/README.md) — IPv4/IPv6 listener contexts and `network_session::sendto`.
- [DTLS server](../dtlsserver/README.md) — secure datagram transport layered over UDP.
- [Network-server implementation](../../../sdk/net/server/README.md) — higher-level event/session management.

## 6. References

- `run_server.cpp` — socket setup, multiplexer callback, receive/send and shutdown.
- `sample.cpp`, `sample.hpp` — shared applet configuration.
- `CMakeLists.txt` — executable target.

## 7. Developer Notes

The current source comments identify IPv4-only support. Preserve that constraint in user-facing descriptions unless an IPv6 implementation and test path are added and verified. The Windows asynchronous receive path deserves separate testing from the Linux readiness path.
