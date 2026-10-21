## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Scope: runnable UDP server applet
```

# Network-server-integrated UDP server applet

## 1. Role

`udpserver2` demonstrates UDP datagram handling through hotplace's `network_server` abstraction. Unlike `udpserver1`, the source opens both IPv4 and IPv6 listener contexts and receives the peer address and `network_session` through the shared consumer callback.

It is a plain UDP echo example, not a DTLS endpoint.

## 2. Model

### Listener and datagram flow

```text
echo_server()
    ├── open AF_INET listener context
    ├── open AF_INET6 listener context
    ├── start consumer loops
    └── start event loops
             │
             ▼
consumer_routine(mux_dgram)
    ├── read peer address from event arguments
    ├── format/log peer and datagram bytes
    └── session->sendto(bytes, peer address)
             │
             ▼
      response datagram to the sender
```

The consumer receives the event socket wrapper, buffer and size, session object, and peer-address pointer. The response uses `network_session::sendto`, keeping the example at the network-server abstraction level rather than calling the platform `sendto` directly.

## 3. Important behavior and lifetime

- Both address families are opened on the configured port; actual IPv6 availability still depends on OS configuration and socket behavior.
- The callback handles only `mux_dgram` in this example. It logs the peer and payload, then sends the same bytes to the captured address.
- The `.run` marker controls the server loop. Shutdown breaks both event loops and consumer loops before closing both contexts.
- `server_conf` sets event, network, and consumer concurrency. These settings describe the server's dispatch model; they do not by themselves prove race-free behavior under every load.

Datagram boundaries are preserved by the echo path. The applet does not demonstrate reliable delivery, ordered messages, congestion control or DTLS security.

## 4. Example from the source

Send a datagram to the configured port using either IPv4 or IPv6 where supported. The source path is `echo_server` → `network_server.open(AF_INET/AF_INET6)` → `consumer_routine(mux_dgram)` → `session->sendto`. Compare the received echo and source address to verify the basic integration.

The source-level flow does not establish that IPv6 was exercised on every platform. This documentation update did not run a live client/server test.

## 5. Relationships

- [Direct multiplexer UDP example](../udpserver1/README.md) — platform-level receive/send path, IPv4-only.
- [DTLS server](../dtlsserver/README.md) — secure datagram integration.
- [Network-server implementation](../../../sdk/net/server/README.md) — shared event loops and session lifecycle.
- [TLS server](../tlsserver/README.md) — stream-oriented secure transport for comparison.

## 6. References

- `run_server.cpp` — dual listener setup, event loops and datagram callback.
- `sample.cpp`, `sample.hpp` — shared applet configuration.
- `CMakeLists.txt` — executable target.

## 7. Developer Notes

The source advertises IPv4 and IPv6 support, but that is a source-level capability description, not proof of a successful IPv6 runtime test. Keep runtime results tied to the corresponding report/environment or live integration record.
