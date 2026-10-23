## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: runnable integration examples
```

# Test applets

## 1. Role

`test/applet` contains runnable programs that compose SDK components into servers or clients. Unlike isolated testcase programs, applets expose integration paths for transport, session handling, secure sockets, application protocols, and interaction with independent peers. The `authenticode` applet is a separate file-signature verification tool, not part of the network progression.

The source comments identify the main stream-server progression as `tcpserver1 → tcpserver2 → tlsserver → httpserver1 → httpserver2`. The datagram progression is `udpserver1 → udpserver2 → dtlsserver`.

## 2. Integration Model

### Server progression

| Applet | Integration focus |
|---|---|
| [`tcpserver1`](tcpserver1/README.md) | TCP echo path using the platform multiplexer directly |
| [`tcpserver2`](tcpserver2/README.md) | TCP echo path through `network_server` |
| [`tlsserver`](tlsserver/README.md) | TLS server through `network_server`, with OpenSSL or trial socket adapter selection |
| [`httpserver1`](httpserver1/README.md) | `http_server` integration with HTTP/1.1 |
| [`httpserver2`](httpserver2/README.md) | `http_server` integration with HTTP/2 |
| [`udpserver1`](udpserver1/README.md) | UDP datagram handling using the platform multiplexer directly |
| [`udpserver2`](udpserver2/README.md) | UDP datagram handling through `network_server`, with IPv4 and IPv6 listener paths |
| [`dtlsserver`](dtlsserver/README.md) | DTLS 1.2 server through `network_server` |

The stream progression moves from direct multiplexer handling to the shared server/session abstraction, then adds TLS and HTTP. The datagram progression moves from direct UDP handling to `network_server`, then adds DTLS.

For a source-level comparison of how integration responsibilities move across `tcpserver1`, `tcpserver2`, `tlsserver`, `httpserver1`, and `httpserver2`, see [Server integration evolution](integration-evolution.md). It also briefly compares the UDP/DTLS side branch.

### Shared transport and protocol layers

`network_server` coordinates server-side event processing and sessions. TCP and TLS use stream connections; UDP and DTLS use datagram-oriented paths. TLS and DTLS applets configure secure-socket implementations, while `http_server` builds on the server/session layer and adds HTTP protocol handling.

QUIC also uses UDP as its transport, but has its own packet/frame and TLS 1.3 integration. It is not the plain UDP echo path or DTLS. The `netclient` QUIC option does not by itself establish a matching QUIC server applet or complete end-to-end QUIC coverage.

The secure server applets select between OpenSSL-backed and trial socket adapters in their source. These are alternative implementation paths selected by configuration, not evidence that every protocol, certificate, and client combination behaves identically.

### Build and implementation entry points

`test/applet/CMakeLists.txt` defines the applet build set. Each applet's `CMakeLists.txt`, `sample.cpp`, and server/client implementation show its executable setup and integration path. The relevant SDK documents are linked from each applet README.

## 3. Interoperability

[`netclient`](netclient/README.md) is the project's peer-side client applet. Its source exposes options for TCP, UDP, TLS 1.2, TLS 1.3, DTLS, and QUIC, with a trial option for applicable secure paths. The available option list describes implementation paths; it does not prove that every client/server combination has been exercised.

External peers used by the applet scenarios include OpenSSL command-line tools such as `s_client` and `s_server`, and HTTP clients such as curl and browsers. The strongest retained interoperability evidence is currently associated with `tlsserver`, `httpserver1`, and `httpserver2`; see their per-applet evidence links.

- [TLS server evidence](tlsserver/README.md) — OpenSSL `s_client` transcript and captured TLS/application-data exchange.
- [HTTP/1.1 evidence](httpserver1/README.md) — curl client trace and server-side trace for a recorded HTTP/1.1 exchange.
- [HTTP/2 evidence](httpserver2/README.md) — curl client trace and server-side trace for a recorded HTTP/2 exchange.

The retained artifacts describe specific client, adapter, certificate, protocol, and source configurations. They must not be generalized to every backend or peer. A possible test procedure is not itself a recorded result.

## 4. Relationships

- [`sdk/net/server`](../../sdk/net/server/README.md) — multiplexer integration, event processing, session lifetime, and protocol dispatch.
- [`sdk/net/basic`](../../sdk/net/basic/README.md) — socket implementations and adapters.
- [`sdk/net/tls`](../../sdk/net/tls/README.md) — TLS, DTLS, and related secure-protocol implementation.
- [`sdk/net/http`](../../sdk/net/http/README.md) — HTTP server, HTTP/1.1, HTTP/2, routing, and message handling.
- [`test/testcase`](../testcase/README.md) — automated component and protocol testcase programs.
- [`etc/cert`](../../etc/cert/README.md) — certificate and key fixtures used by applicable applets.
