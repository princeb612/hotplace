## Publication

```text
hotplace source tree
Edition 1 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Scope: source-level evolution across server applets
```

# Server integration evolution

## 1. Role

This document compares the implementation boundaries across `tcpserver1`, `tcpserver2`, `tlsserver`, `httpserver1`, and `httpserver2`. The sequence is identified in the applet source comments; it is an architectural reading of the examples, not a claim that every implementation was introduced in this exact commit order.

The central change is **where integration work is owned**: direct socket-event handling → shared network-server/session handling → secure transport → HTTP request/response handling → HTTP/2.

## 2. Data Model

| Applet | Main data crossing the callback boundary | Main configuration / integration objects |
|---|---|---|
| `tcpserver1` | `netsocket_event_t`: client socket, peer address, and Windows overlapped read buffer | `accept_context_t`, platform multiplexer context |
| `tcpserver2` | `netsocket_t` event wrapper, received byte buffer and size | `network_server`, IPv4/IPv6 network multiplexer contexts, `ipaddr_acl`, `server_conf` |
| `tlsserver` | `network_session` and received application-data buffer | `server_socket_adapter`, TLS server socket configuration, protocol/certificate/cipher options |
| `httpserver1` | `http_request` / `http_response` with headers, URI/query, body and status | `http_server_builder`, `http_router`, `html_documents`, route-specific authentication providers, `http_authentication_resolver`, OAuth 2.0 providers |
| `httpserver2` | Shared `http_request` / `http_response` and `http_header`, with HTTP/2 stream context | `http_server_builder` with HTTP/2 enabled, `http_router`, `html_documents`, server-push resources; no applet-level authentication-provider setup |

These are the useful comparison points, not a complete inventory of every local variable. The lower-level socket and event objects still exist below the higher-level callbacks; the progression changes which layer the applet has to manipulate directly.

## 3. Behavior Model

### 3.1 Progression at a glance

```text
tcpserver1
  platform socket + multiplexer
  accept / bind / read / echo / unbind / close
        │ move event and connection coordination behind an abstraction
        ▼
tcpserver2
  network_server + netsocket_t callback
  accept policy (ipaddr_acl) / read / echo / disconnect
        │ keep server/session path; add secure-socket adapter
        ▼
tlsserver
  network_server + TLS server_socket
  TLS configuration / secure session / echo application data
        │ keep secure transport; add HTTP request processing
        ▼
httpserver1
  http_server_builder + HTTP/1.1
  parse request / route / compose response / respond
        │ use the HTTP server path with HTTP/2 enabled
        ▼
httpserver2
  http_server_builder + HTTP/2
  HTTP/2 request handling / route / compose response / respond
```

### 3.2 `tcpserver1` — the applet owns socket events

Source: [`tcpserver1/run_server.cpp`](tcpserver1/run_server.cpp).

This is the most explicit transport-level example. It accepts client sockets, associates them with the platform multiplexer, receives bytes, echoes them, and unbinds/closes sockets on disconnect. The `netsocket_event_t` context carries the client socket and peer address; on Windows it also includes the overlapped read buffer. Linux epoll and Windows IOCP follow different event mechanics, so the platform paths should not be treated as one identical implementation.

The important boundary is that the applet itself owns the event-context lifecycle and much of the platform-specific socket flow.

### 3.3 `tcpserver2` — connection coordination moves into `network_server`

Source: [`tcpserver2/run_server.cpp`](tcpserver2/run_server.cpp).

The applet opens `network_server` contexts for both `AF_INET` and `AF_INET6`, registers an accept-control callback, and starts event and consumer loops. Its consumer receives the socket wrapper and payload, then echoes the bytes. The sample's `ipaddr_acl` whitelist permits `127.0.0.1` and `::1`, making the access-policy hook visible in the example.

Compared with `tcpserver1`, the applet no longer builds its main path around its own per-client event context and explicit platform-specific bind/read/close sequence. It configures and uses a shared server abstraction instead. The abstraction does not make application policy disappear: the accept callback and echo behavior remain applet responsibilities.

### 3.4 `tlsserver` — secure transport is configured beneath the application callback

Source: [`tlsserver/run_server.cpp`](tlsserver/run_server.cpp), [`tlsserver/sample.cpp`](tlsserver/sample.cpp).

The server continues to use `network_server` and a consumer callback, but configures a TLS server socket through a selected adapter. Command-line options choose the trial or OpenSSL-backed path, allowed TLS versions, certificate family, cipher suite, supported group, and optional key logging.

The echo callback sends application bytes through `network_session::send`; it does not implement TLS handshake or record protection itself. Those responsibilities belong to the secure-socket and session layers. This is the key separation: the same simple application behavior can sit above a substantially more involved transport.

### 3.5 `httpserver1` — HTTP semantics, routing, and authentication meet at the application boundary

Source: [`httpserver1/run_server.cpp`](httpserver1/run_server.cpp), [`httpserver1/sample.cpp`](httpserver1/sample.cpp).

The applet uses `http_server_builder` to configure HTTP and HTTPS listeners, the selected socket adapter, TLS settings, and the application callback. The callback receives a parsed `http_request`; for the secure path it constructs `http_response(request)`, calls `http_router::route()`, and sends the result through the session. Plain HTTP requests follow the applet's redirect-to-HTTPS path instead.

The router is more than a URI-to-function table in this example. Route registrations attach Basic, Digest (including a user-hash variant), and Bearer authentication providers. The applet separately populates `http_authentication_resolver` with sample credentials and token values, then configures OAuth 2.0 grant providers, endpoint paths, token-endpoint Basic authentication, and an example callback that exchanges an authorization code through `http_client`. The provider/resolver boundary separates scheme-specific request authentication from credential lookup; a failed authentication challenges the request and prevents normal handler dispatch.

The OAuth-related browser path in `index.html` has been used for a basic lab-level functional check. This is evidence of local exercise, not independent OAuth interoperability testing or a performance/operational validation suitable for pilot deployment. Those remain separate follow-up steps rather than implied properties of the implementation.

The shared HTTP objects make this composition possible without mixing layers: `http_header` carries message fields, `http_request` exposes parsed method/URI/query/header/body data, and `http_response` composes status, headers, and content while retaining request context. `html_documents` supplies configured file-backed content as an optional router fallback, while explicit API and authentication routes remain handler registrations. This is the point where the example moves beyond secure transport into application-level protocol integration.


### 3.6 `httpserver2` — the same application model over HTTP/2 streams

Source: [`httpserver2/run_server.cpp`](httpserver2/run_server.cpp), [`httpserver2/sample.cpp`](httpserver2/sample.cpp).

The HTTP/2 example retains the `http_server_builder`, adapter selection, request callback, router, and response pattern. It disables the plain HTTP listener, enables HTTPS with `enable_h2(true)`, and configures packet-size constraints for the HTTP and HTTP/2 protocol objects. The applet registers HTML/JSON/API handlers, configures `html_documents` with a document root, content types, and default `index.html`, and adds server-push resources.

The common application objects do not expose raw HTTP/2 frames to the handler. The protocol/session path assembles a completed `http_request` with stream context; the callback checks for a non-null request, creates `http_response(request)`, routes it, and calls `respond(session)`. The response path uses the request's protocol version and stream identity to serialize the response for the proper HTTP/2 stream.

This applet demonstrates reuse of the same HTTP semantic layer—`http_header`, `http_request`, `http_response`, `http_router`, and `html_documents`—with different protocol framing underneath. Unlike `httpserver1`, it does not register the Basic/Digest/Bearer authentication providers. The shared router supports authentication, but that capability should not be confused with authentication being configured in every applet.


### 3.7 Side branch: datagram integration

The UDP/DTLS examples provide a useful contrast, but they are not another step in the TCP → TLS → HTTP stream sequence:

```text
udpserver1
  UDP socket + multiplexer + recvfrom/sendto
        │
        ▼
udpserver2
  network_server + mux_dgram + session->sendto
        │ add secure datagram transport
        ▼
dtlsserver
  DTLS server_socket + mux_dgram + session->sendto
```

- [`udpserver1`](udpserver1/README.md) handles IPv4 UDP datagrams directly through the platform multiplexer and preserves the sender address for `sendto`.
- [`udpserver2`](udpserver2/README.md) uses `network_server` for IPv4 and IPv6 listener contexts and sends the response through `network_session::sendto`.
- [`dtlsserver`](dtlsserver/README.md) adds DTLS 1.2 through the secure-socket path while retaining datagram-oriented callback semantics.

This branch demonstrates that the network-server abstraction also serves datagram traffic. It does not turn UDP into a stream, and DTLS does not use the stream-oriented `session->send` path shown by `tlsserver`.

## 4. Relationships

- [Applet overview](README.md) — inventory and broader purpose of runnable integration examples.
- [TCP server with direct multiplexer handling](tcpserver1/README.md) and [TCP server using `network_server`](tcpserver2/README.md) — per-applet setup and caveats.
- [TLS server](tlsserver/README.md), [HTTP/1.1 server](httpserver1/README.md), and [HTTP/2 server](httpserver2/README.md) — per-applet options and interoperability records.
- [UDP server with direct multiplexer handling](udpserver1/README.md), [UDP server using `network_server`](udpserver2/README.md), and [DTLS server](dtlsserver/README.md) — datagram-side comparison.
- [Network server implementation](../../sdk/net/server/README.md) — shared event processing, session abstraction, and server lifecycle.
- [TLS/DTLS implementation](../../sdk/net/tls/README.md) and [HTTP implementation](../../sdk/net/http/README.md) — secure transport and application-protocol layers.

## 5. Reading the progression

The examples illustrate a shift in integration responsibility, not a simple ladder where each later applet replaces the earlier one:

1. **Socket mechanics are explicit** in `tcpserver1`.
2. **Connection and event coordination are abstracted** by `network_server` in `tcpserver2`.
3. **Secure transport is selected and configured below the application callback** in `tlsserver`.
4. **Application bytes are interpreted as protocol messages** in `httpserver1`.
5. **A different HTTP version is integrated through the same high-level server boundary** in `httpserver2`.

The applets remain useful side by side because each exposes a different boundary. This comparison is based on source inspection; it does not claim that every configuration or interoperability scenario was executed during this documentation change.
