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

`test/applet` contains runnable programs that bring SDK components together as servers or clients. Their purpose is broader than isolated testcase assertions: they provide executable integration points for exploring transport, session handling, secure sockets, and application protocols, including interaction with independent peers. `authenticode` is a separate verification applet: it exercises file-signature verification with a supplied target file and trust certificate, rather than following the network server/client progression.

The source comments in the server applets give an explicit reading order: `tcpserver1 → tcpserver2 → tlsserver → httpserver1 → httpserver2`. The UDP path has a related progression: `udpserver1 → udpserver2 → dtlsserver`.

## 2. Integration model

### Server progression

| Applet | Integration focus |
|---|---|
| [`tcpserver1`](tcpserver1/README.md) | TCP echo path using the platform multiplexer directly |
| [`tcpserver2`](tcpserver2/README.md) | TCP echo path through `network_server` |
| [`tlsserver`](tlsserver/README.md) | TLS server through `network_server`, with OpenSSL or trial socket adapter selection |
| [`httpserver1`](httpserver1/README.md) | `http_server` integration with HTTP/1.1 |
| [`httpserver2`](httpserver2/README.md) | `http_server` integration with HTTP/2 |
| [`udpserver1`](udpserver1/README.md) | UDP datagram handling using the platform multiplexer directly |
| [`udpserver2`](udpserver2/README.md) | UDP datagram handling through `network_server`, with IPv4 and IPv6 paths |
| [`dtlsserver`](dtlsserver/README.md) | DTLS 1.2 server through `network_server` |

The two progressions show different integration boundaries. The first moves from direct multiplexer use to the shared server abstraction and then to TLS and HTTP. The UDP progression moves from direct datagram handling to `network_server`, then to DTLS. The exact implementation details belong in each applet README and the corresponding SDK source documentation.

### Shared transport and protocol layers

`network_server` coordinates server-side event processing and sessions. TCP and TLS use stream connections; UDP and DTLS use datagram-oriented paths. The TLS and DTLS applets configure secure-socket implementations, while `http_server` builds on the server/session layer and adds HTTP protocol handling. QUIC also uses UDP as its transport, but has its own packet/frame and TLS 1.3 integration; it is not the plain UDP echo path or DTLS. The `netclient` QUIC option does not by itself establish a matching QUIC server applet or complete end-to-end QUIC coverage.

The secure server applets select between the OpenSSL-backed and trial socket adapters in their source. These are alternative implementation paths selected by configuration, not evidence that every protocol, certificate, and client combination behaves identically.

## 3. Peer-side integration

[`netclient`](netclient/README.md) is the project's peer-side client applet. Its source exposes protocol selection for TCP, UDP, TLS 1.2, TLS 1.3, DTLS, and QUIC, as well as a trial option for the relevant secure paths. It can be used to examine the client/server relationship from the opposite endpoint; the supported option list alone does not imply that every applet/protocol combination has been exercised.

External peers provide additional interoperability paths where applicable:

- OpenSSL command-line clients and servers, including `s_client` and `s_server`.
- HTTP clients and browsers such as curl, wget, Chrome, and Edge for the HTTP server applets.

Record only the client/server combinations and outcomes supported by existing notes or captured artifacts. A possible test procedure is not itself a recorded result.

## 4. Existing evidence and test records

Captured evidence is present in the subdirectories of `tlsserver`, `httpserver1`, and `httpserver2`. Those materials document particular recorded scenarios; they should not be generalized to every adapter, protocol, certificate, or external client.

For other server applets, document the implementation and the test method available from the source or existing maintainer notes. Prior test experience without a retained log or capture should not be presented as preserved evidence.

## 5. Relationships

- [`sdk/net/server`](../../sdk/net/server/README.md) — multiplexer integration, event processing, session lifetime and protocol dispatch.
- [`sdk/net/basic`](../../sdk/net/basic/README.md) — socket implementations and adapters.
- [`sdk/net/tls`](../../sdk/net/tls/README.md) — TLS, DTLS and related secure-protocol implementation.
- [`sdk/net/http`](../../sdk/net/http/README.md) — HTTP server, HTTP/1.1, HTTP/2, routing and message handling.
- [`test/testcase`](../testcase/README.md) — automated component and protocol testcase programs.
- [`etc/cert`](../../etc/cert/README.md) — certificate and key fixtures used by applicable applets.

## 6. References

- `test/applet/CMakeLists.txt` — applets included in the build.
- Each applet's `CMakeLists.txt`, `sample.cpp`, and server/client implementation — executable setup and integration path.
- The `@sa` comments in `tcpserver1`, `tcpserver2`, `tlsserver`, `httpserver1`, and `httpserver2` — maintainer-provided server progression.
