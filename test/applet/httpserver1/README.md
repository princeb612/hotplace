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

`httpserver1` is the HTTP/1.1 server integration example. It uses `http_server` and its routing layer, with either the OpenSSL-backed socket adapter or the trial adapter selected by the applet options.

It follows `tcpserver1`, `tcpserver2`, and `tlsserver` in the server progression. The source comments identify this order explicitly.

## 2. Integration path

```text
command-line options
    └─ select OpenSSL or trial socket adapter
             │
             ▼
       http_server_builder
             │
             ├─ configure listeners and TLS certificate
             ├─ configure HTTP protocol
             └─ build/start http_server
                       │
                       ▼
              HTTP request callback
                       │
                       ├─ http_router
                       └─ http_response
```

The applet source registers routes for static content, API responses, and authentication-related flows. The server callback routes parsed requests and sends the composed response through the HTTP server/session path. HTTP parsing and request/response handling belong to `sdk/net/http`; socket events and sessions are provided by the lower network layers.

## 3. Execution

The applet's command-line options are defined in `sample.cpp`. Relevant options include `-r` to run the server, `-h` and `-s` for the plain HTTP and HTTPS ports, `-T` for the trial adapter, `-cert` for certificate selection, and `-k` for TLS key logging.

Examples from the applet's documented usage:

```sh
./test-httpserver1 -r -k --trace
./test-httpserver1 -r -k --trace -T -cert mldsa
```

The executable suffix and runtime working directory depend on the build environment. Certificate/key files must be available where the applet loads them. The applet uses a `.run` marker for its run-loop lifetime.

## 4. Interoperability and existing evidence

The HTTP server can be exercised by external peers, including Chrome, Edge, curl, and wget. `netclient` provides a project-local peer for the supported client-side protocol paths. Which client, adapter, certificate, and protocol combination was used should be taken from the corresponding record rather than inferred from the available options.

The `pcap/` directory preserves one specific ML-DSA certificate scenario:

- [Capture index](pcap/README.md)
- [Client-side trace](pcap/httpserver1-mldsa-client.md)
- [Server-side trace](pcap/httpserver1-mldsa-server.md)
- `httpserver1-mldsa.pcapng`
- `sslkeylog.txt`

The recorded client trace shows TLS 1.3, ALPN `http/1.1`, `GET /`, and an HTTP `200 OK` response. The server trace records the trial adapter and `-cert mldsa` configuration. These files describe that captured exchange only; they are not a report for every adapter, certificate family, client, or source revision.

TLS key-log material contains session secrets and should be treated as sensitive diagnostic data.

## 5. Relationships

- [TCP server using the multiplexer](../tcpserver1/README.md) — direct socket-event handling.
- [TCP server using network_server](../tcpserver2/README.md) — shared server/session abstraction.
- [TLS server](../tlsserver/README.md) — secure transport integration before HTTP.
- [HTTP/2 server](../httpserver2/README.md) — the related applet using the same higher-level HTTP server abstraction with HTTP/2.
- [Network client](../netclient/README.md) — project-local peer.
- [Network server](../../../sdk/net/server/README.md), [HTTP](../../../sdk/net/http/README.md), and [TLS/DTLS/QUIC](../../../sdk/net/tls/README.md) — the underlying implementation layers.

## 6. Source map

- `sample.cpp`, `sample.hpp` — command-line options and applet setup.
- `run_server.cpp` — adapter selection, HTTP server construction, routes, and request handling.
- `index.html`, `signin.html`, `style.css` — sample web resources.
- `CMakeLists.txt` — executable target and resource staging.
