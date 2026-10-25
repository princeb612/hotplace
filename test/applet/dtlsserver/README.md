## Publication

```text
hotplace source tree
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: runnable DTLS server applet
```

# DTLS 1.2 server applet

## 1. Role

`dtlsserver` is a runnable DTLS 1.2 echo server over UDP. It exercises the datagram-oriented secure-socket path through `network_server`, with either the OpenSSL-backed adapter or the trial adapter. It is a protocol integration applet, not a general-purpose production service or a complete DTLS conformance suite.

## 2. Integration Model

### Datagram event path

```text
UDP datagram + peer address
          │
          ▼
network_server / DTLS server_socket
          │
          ▼
consumer_routine(mux_dgram)
          │
          ├── log peer address and received bytes
          └── session.sendto(bytes, peer address)
                       │
                       ▼
              response datagram to peer
```

The callback uses the peer address delivered with the datagram and replies with `session->sendto`. This differs from the stream-oriented `session->send` path used by the TLS echo server.

### Configuration, lifecycle, and limits

The server configures the socket scheme as DTLS plus TLS 1.2, then adds either the trial or OpenSSL adapter according to `-T`. The trial path loads the RSA and ECDSA certificate material used for the TLS 1.2 cipher-suite configuration. The applet creates a `.run` marker while active; its documented stop procedure removes that marker.

Because DTLS runs over datagrams, peer address and datagram boundaries are part of the callback contract. A logged datagram and an echo response do not by themselves prove all handshake retransmission, record reordering, fragmentation, loss-recovery, or peer-migration scenarios are handled correctly.

Start the server:

```sh
./test-dtlsserver -r -k --trace
```

Stop it by removing the `.run` marker. The executable name and runtime environment depend on the active build.

### Implementation entry points

- `run_server.cpp` — DTLS socket setup and datagram callback.
- `sample.cpp`, `sample.hpp` — command-line and logging configuration.
- `CMakeLists.txt` — applet build target.

## 3. Interoperability

The server can be exercised with either an OpenSSL DTLS 1.2 client or hotplace's project-local [`netclient`](../netclient/README.md). For `netclient`, select the DTLS path with `-P dtls` and target the server address and port (the applet's documented default is `127.0.0.1:9000`). The external-peer example is:

```sh
openssl s_client -dtls1_2 -connect 127.0.0.1:9000
```

Send application data after the handshake to observe the echo behavior. These are integration procedures; they were not executed as part of this documentation update, and no retained capture or applet-specific report is identified here. Do not treat the procedures alone as recorded interoperability evidence.

## 4. Relationships

- [TLS/DTLS/QUIC implementation](../../../sdk/net/tls/README.md) — DTLS record/session behavior.
- [Network server](../../../sdk/net/server/README.md) — server lifecycle and session management.
- [UDP server examples](../udpserver1/README.md) and [network-server UDP example](../udpserver2/README.md) — plain datagram handling before adding DTLS.
- [Network client applet](../netclient/README.md) — shared client integration entry point.

## 5. References

- RFC 6347 — Datagram Transport Layer Security (DTLS) 1.2.
