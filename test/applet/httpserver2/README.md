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

`httpserver2` is the HTTP/2 server integration example. It uses the `http_server_builder` to configure the HTTP server, select a socket adapter, enable HTTP/2, and register request handlers. It follows `httpserver1`, which uses the same higher-level server abstraction with HTTP/1.1.

## 2. Integration path

```text
OpenSSL or trial socket adapter
             │
             ▼
      http_server_builder
             │
             ├─ configure HTTPS and certificate
             ├─ enable HTTP/2
             └─ build/start http_server
                       │
                       ▼
              HTTP/2 request handling
                       │
                       ├─ http_router
                       └─ http_response
```

In `run_server.cpp`, the builder enables HTTP/2 and configures the HTTP and HTTP/2 protocol packet-size constraints. The request callback routes requests through `http_router` and sends the composed response through the HTTP server/session path. The source also registers HTML, JSON, and default API handlers and HTTP/2 server-push resources.

The shared server/session layer is described in [`sdk/net/server`](../../../sdk/net/server/README.md); HTTP framing, HTTP/2 sessions, and HPACK are described in [`sdk/net/http`](../../../sdk/net/http/README.md).

## 3. Execution

The command-line options are defined in `sample.cpp`. They include `-r` to run the server, `-T` to select the trial adapter, `-cert` to select certificate material, and `-k` for TLS key logging. The applet uses a `.run` marker for its run-loop lifetime.

An HTTPS connection by itself does not identify the HTTP version selected. The recorded client configuration and protocol negotiation are the relevant facts for each interoperability scenario.

## 4. Existing evidence

The `pcap/` directory contains an HTTP/2 capture and associated client/server trace notes:

- [Capture index](pcap/README.md)
- `httpserver2-mldsa.pcapng`
- [Client-side trace](pcap/httpserver2-mldsa-client.md)
- [Server-side trace](pcap/httpserver2-mldsa-server.md)
- `sslkeylog`

These files describe the captured scenario only; they do not establish compatibility for every browser, adapter, certificate family, or source revision. TLS key-log material contains session secrets and should be treated as sensitive diagnostic data.

## 5. Relationships

- [HTTP/1.1 server](../httpserver1/README.md) — related applet using `http_server` with HTTP/1.1.
- [TLS server](../tlsserver/README.md) — secure transport integration before HTTP.
- [Network client](../netclient/README.md) — project-local peer.
- [Network server](../../../sdk/net/server/README.md), [HTTP](../../../sdk/net/http/README.md), and [TLS/DTLS/QUIC](../../../sdk/net/tls/README.md) — underlying implementation layers.

## 6. Source map

- `sample.cpp`, `sample.hpp` — command-line options and applet setup.
- `run_server.cpp` — adapter selection, builder configuration, request routing, and response handling.
- `index.html` — sample web resource.
- `pcap/` — recorded HTTP/2 scenario and trace notes.
- `CMakeLists.txt` — executable target and resource staging.
