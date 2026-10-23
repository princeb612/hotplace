## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: HTTP/2 server integration applet
```

# HTTP/2 server applet

## 1. Role

`httpserver2` is the HTTP/2 server integration example. It uses `http_server_builder` to configure the HTTP server, select a socket adapter, enable HTTP/2, and register request handlers. It follows `httpserver1`, which uses the same higher-level server abstraction with HTTP/1.1.

## 2. Integration Model

### Integration stack

~~~text
server_socket_builder
  └─ OpenSSL adapter or trial adapter
          │
          ▼
http_server_builder
  ├─ HTTPS listener (IPv4 / IPv6); plain HTTP disabled
  ├─ TLS certificate / cipher configuration
  ├─ enable_h2(true) + HTTP/2 protocol constraints
  └─ build http_server
          │
          ▼
network_server + network_session
          │ HTTP/2 frames / completed request
          ▼
consumer_routine
  └─ http_router::route()
        ├─ URI / status handler
        └─ html_documents fallback
                 │
                 ▼
           http_response::respond()
~~~

The applet uses the same higher-level server builder and application-facing message/router model as httpserver1. Its integration difference is configuration and protocol handling: it disables the plain HTTP listener, enables HTTPS and HTTP/2, and sets packet-size constraints for both HTTP and HTTP/2 protocol objects. HTTP/2 framing, stream state, and header compression remain in the SDK rather than being implemented in the applet callback.

### Shared HTTP application objects

The common message and routing objects remain stable across the two applets; the protocol layer determines how incoming bytes become a completed request and how the response is serialized.

- **http_header** holds the header fields exposed to handlers and populated by response construction. In HTTP/2, header fields travel through HTTP/2 framing and HPACK; the application still works with the common header abstraction.
- **http_request** exposes the method, URI/path/query, headers, body, protocol version, and HTTP/2 stream ID. The callback is invoked only when the HTTP/2 session has assembled a request ready for application handling.
- **http_response** is constructed from that request, preserving the protocol version and stream identity required for a response on the same HTTP/2 stream. The applet composes the status/body and calls respond(session); it does not manually build HTTP/2 frames.
- **http_router** dispatches the request to the registered URI handler and owns optional route authentication, status handlers, document fallback, and HTTP/2 server-push configuration. This applet registers HTML/JSON/API handlers and server-push resources.
- **html_documents** is configured with the document root, content-type mappings, and default index.html. The router may use it as a file-backed fallback when no explicit URI handler matches.

The types and capabilities are shared with httpserver1, but the examples do not configure identical behavior. In particular, httpserver2 registers ordinary URI handlers and document resources but does not register the authentication providers configured in httpserver1.

### Request handling path

In run_server.cpp, the builder enables HTTP/2 and configures HTTP/HTTP/2 protocol packet-size constraints. In consumer_routine, the mux_read path checks that request is non-null, constructs http_response(request), routes the request through http_router, and sends the response. The callback does not parse HTTP/2 frames itself; the protocol/session path has already assembled the request and retained stream context.

### Execution and implementation entry points

Command-line options are defined in sample.cpp. They include -r to run the server, -T to select the trial adapter, -cert to select certificate material, and -k for TLS key logging. The applet uses a .run marker for its run-loop lifetime.

- sample.cpp, sample.hpp — command-line options and applet setup.
- run_server.cpp — adapter selection, builder configuration, request routing, and response handling.
- index.html — sample web resource.
- pcap/ — recorded HTTP/2 scenario and trace notes.
- CMakeLists.txt — executable target and resource staging.

An HTTPS connection by itself does not identify the HTTP version selected. The recorded client configuration and protocol negotiation are the relevant facts for each interoperability scenario.

## 3. Interoperability

The applet can be exercised with HTTP clients such as curl and browsers. Retained evidence for one ML-DSA certificate scenario is available here:

- [Capture index](pcap/README.md)
- [Client-side trace](pcap/httpserver2-mldsa-client.md)
- [Server-side trace](pcap/httpserver2-mldsa-server.md)
- `httpserver2-mldsa.pcapng`
- `sslkeylog`

The recorded curl trace contains an HTTP/2 request for `/` and a `:status: 200` response. The client trace also records HTTP/2 framing and response data; the server trace documents the selected applet configuration. These artifacts describe that captured scenario only and do not establish compatibility for every browser, adapter, certificate family, or source revision. TLS key-log material contains session secrets and should be treated as sensitive diagnostic data.

## 4. Relationships

- [HTTP/1.1 server](../httpserver1/README.md) — related applet using `http_server` with HTTP/1.1.
- [TLS server](../tlsserver/README.md) — secure transport integration before HTTP.
- [Network server](../../../sdk/net/server/README.md), [HTTP](../../../sdk/net/http/README.md), and [TLS/DTLS/QUIC](../../../sdk/net/tls/README.md) — underlying implementation layers.
