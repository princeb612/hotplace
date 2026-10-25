## Publication

```text
hotplace source tree
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: runnable TCP server applet
```

# Network-server-integrated TCP server applet

## 1. Role

`tcpserver2` is the TCP echo-server example built on hotplace's higher-level `network_server` abstraction. Compared with `tcpserver1`, it delegates socket event-loop and session coordination to the network-server layer and demonstrates an accept-policy callback through `ipaddr_acl`.

It remains a plain TCP applet: it does not implement TLS or HTTP.

## 2. Integration Model

### Server setup and callback flow

```text
echo_server()
    ├── configure ipaddr_acl whitelist
    │     ├── 127.0.0.1
    │     └── ::1
    ├── open network_server for AF_INET and AF_INET6
    ├── register accept_handler on both contexts
    ├── start consumer loops and event loops
    │
    ▼
consumer_routine
    ├── mux_connect    → log connection
    ├── mux_read       → log and send bytes to peer socket
    └── mux_disconnect → log disconnect
    │
    ▼
remove .run marker → break loops → close contexts
```

The accept handler calls `acl.determine(client_addr, result)` and sets `CONTINUE_CONTROL` or `STOP_CONTROL` based on the whitelist decision. The example registers loopback addresses, so the policy is deliberately restrictive for local testing.

### Behavior and lifetime

- The server opens IPv4 and IPv6 listener contexts on the configured port and registers the same accept-control policy for both.
- `server_conf` controls event/network/consumer concurrency; source comments note that the concurrent-event setting is relevant to Linux epoll concerns and ignored on Windows.
- The callback receives a `netsocket_t` event object and data buffer. In the read case it writes the bytes back through the event socket; this is a simple echo path, not a framed application protocol.
- The `.run` marker controls the applet lifetime. On shutdown the event and consumer loops are broken and both network contexts are closed.

The loopback whitelist is an example access policy, not a general firewall or a complete address-ACL test. A successful echo does not establish behavior for every IPv4/IPv6 address or backend.

### Execution and implementation entry points

Start the applet with the configured port, then connect from loopback and send a short payload. The source path to follow is `echo_server` → ACL setup → `network_server.open` for each address family → `accept_handler` → `consumer_routine(mux_read)`. The read callback logs and sends received bytes back to the socket.

- `run_server.cpp` — ACL callback, event callback, listener setup, and loop shutdown.
- `sample.cpp`, `sample.hpp` — applet options and shared setup.
- `CMakeLists.txt` — executable target.

The exact executable and command-line defaults come from `sample.cpp` and the active build. This documentation update did not run a live client/server test.

## 3. Interoperability

The project-local [netclient](../netclient/README.md) can exercise the echo path from loopback; the sample whitelist permits `127.0.0.1` and `::1`. No retained client transcript, capture, or applet-specific report is identified here. A source-level IPv4/IPv6 listener path is not proof that both address families were successfully exercised on every platform.

## 4. Relationships

- [Low-level TCP server](../tcpserver1/README.md) — direct multiplexer/event-context handling.
- [TLS server](../tlsserver/README.md) — secure stream integration.
- [Network-server implementation](../../../sdk/net/server/README.md) — event loops, accept control, and session management.
- [IP address ACL](../../../sdk/net/basic/README.md) — address-policy implementation.

## 5. References

## 6. Developer Notes

The source's whitelist currently permits `127.0.0.1` and `::1`. If this applet is adapted for non-loopback tests, update the rule set intentionally and test both address families; do not quietly treat the local-only policy as a production access-control default.
