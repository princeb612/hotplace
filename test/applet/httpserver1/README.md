## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: HTTP/1.1 server integration applet
```

# HTTP/1.1 server applet

## 1. Role

`httpserver1` is the HTTP/1.1 server integration example. It uses `http_server` and its routing layer, with either the OpenSSL-backed socket adapter or the trial adapter selected by the applet options. It follows `tcpserver1`, `tcpserver2`, and `tlsserver` in the source-identified server progression.

## 2. Integration Model

### Integration stack

~~~text
server_socket_builder
  └─ OpenSSL adapter or trial adapter
          │
          ▼
http_server_builder
  ├─ HTTP + HTTPS listeners (IPv4 / IPv6)
  ├─ TLS certificate / cipher configuration
  ├─ HTTP protocol and request callback
  └─ build http_server
          │
          ▼
network_server + network_session
          │ completed HTTP request
          ▼
consumer_routine
  ├─ plain HTTP -> redirect to HTTPS
  └─ HTTPS -> http_router::route()
                  │
                  ├─ authentication provider + resolver (when registered)
                  ├─ URI / status handler
                  └─ html_documents fallback
                          │
                          ▼
                    http_response::respond()
~~~

The applet composes the transport adapter, http_server, HTTP request handling, routing, authentication, and response generation. The callback receives an already parsed http_request; it is not responsible for interpreting arbitrary socket reads as HTTP messages. The network/session and HTTP protocol layers below it handle connection events and protocol-specific message processing.

### Shared HTTP application objects

httpserver1 and httpserver2 use the same application-facing HTTP model, even though their wire-protocol handling differs.

- **http_header** stores request and response header fields. The applet reads fields such as Host, adds response headers such as Location, and the authentication code consumes scheme-specific Authorization values.
- **http_request** represents the parsed request: method, URI/path/query, headers, body, protocol version, and (for HTTP/2) stream context. Route handlers inspect this object instead of parsing the wire representation themselves.
- **http_response** is constructed from the request, then populated with a status, headers, and content. respond(session) sends it through the active HTTP path; the originating request supplies protocol/stream context needed by HTTP/1.1 or HTTP/2 response handling.
- **http_router** maps URI paths and status codes to application callbacks. A route may attach an authentication provider; the router performs that authentication before dispatching to the normal handler. It can also consult html_documents when no registered URI handler matches.
- **html_documents** is the router's optional file-backed content source. The applet configures a document root, extension-to-content-type mappings, and index.html as the default document. It is a content fallback, not the request parser or the route table.

### Authentication provider and resolver integration

Authentication is an explicit application layer in httpserver1. The route registrations attach providers to endpoints:

| Route | Provider / purpose |
|---|---|
| /auth/basic | Basic authentication |
| /auth/digest | Digest authentication using the configured realm, algorithm, and QOP |
| /auth/userhash | Digest authentication with user-hash behavior enabled |
| /auth/bearer | Bearer-token authentication |
| /client/cb | Application callback that processes OAuth-related query parameters |

The applet then populates http_authentication_resolver with the credentials or token values used by the providers. The resolver is separate from the provider: the provider interprets the scheme and checks the presented authentication data, while the resolver supplies the configured credential lookup. If authentication fails, the router/provider path can generate an authentication challenge and stop normal route dispatch; successful authentication allows the registered route handler to run.

The applet also configures OAuth 2.0 grant providers, authorization/token/sign-in endpoints, token-endpoint Basic authentication, and example OAuth credentials. The callback handler demonstrates an authorization-code token request through http_client and a simplified implicit-flow response. The applet's index.html provides a browser-facing path used for basic lab-level functional checks of this integration. That evidence shows the feature was exercised; it does not establish interoperability with independent OAuth implementations, performance under load, operational stability, or suitability for a pilot deployment. Treat this as a study implementation with limited local verification, not production-ready identity management or a complete deployment-ready OAuth service.

### Request handling and response path

consumer_routine handles the server event callback. For the secure listener it creates http_response(request), calls http_router::route(session, request, &response), and responds through the session. For the plain HTTP listener, the current path redirects the request to the configured HTTPS port instead of running the authenticated route handlers. The protocol parser and http_server deliver request objects; the callback chooses the application path.

### Execution and options

Command-line options are defined in sample.cpp. Relevant options include -r to run the server, -h and -s for the plain HTTP and HTTPS ports, -T for the trial adapter, -cert for certificate selection, and -k for TLS key logging.

~~~sh
./test-httpserver1 -r -k --trace
./test-httpserver1 -r -k --trace -T -cert mldsa
~~~

The executable suffix and runtime working directory depend on the build environment. Certificate/key files must be available where the applet loads them. The applet uses a .run marker for its run-loop lifetime.

### Implementation entry points

- sample.cpp, sample.hpp — command-line options and applet setup.
- run_server.cpp — adapter selection, HTTP server construction, routes, authentication providers/resolver, and request handling.
- index.html, signin.html, style.css — sample web resources.
- CMakeLists.txt — executable target and resource staging.

## 3. Interoperability

External peers include curl, wget, Chrome, and Edge. The retained evidence is one specific ML-DSA certificate scenario:

- [Capture index](pcap/README.md)
- [Client-side trace](pcap/httpserver1-mldsa-client.md)
- [Server-side trace](pcap/httpserver1-mldsa-server.md)
- `httpserver1-mldsa.pcapng`
- `sslkeylog.txt`

The recorded client trace shows TLS 1.3, ALPN `http/1.1`, `GET /`, and an HTTP `200 OK` response. The server trace records the trial adapter and `-cert mldsa` configuration. These artifacts describe that captured exchange only; they are not evidence for every adapter, certificate family, client, or source revision.

TLS key-log material contains session secrets and should be treated as sensitive diagnostic data. The availability of other client options does not imply that those combinations have been recorded or rerun.

## 4. Relationships

- [TCP server using the multiplexer](../tcpserver1/README.md) — direct socket-event handling.
- [TCP server using network_server](../tcpserver2/README.md) — shared server/session abstraction.
- [TLS server](../tlsserver/README.md) — secure transport integration before HTTP.
- [HTTP/2 server](../httpserver2/README.md) — the related applet using the same higher-level HTTP server abstraction with HTTP/2.
- [Network server](../../../sdk/net/server/README.md), [HTTP](../../../sdk/net/http/README.md), and [TLS/DTLS/QUIC](../../../sdk/net/tls/README.md) — underlying implementation layers.
