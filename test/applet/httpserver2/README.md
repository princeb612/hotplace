#### HTTP/2 simple server

```
# run (libssl)
./test-httpserver2 -r -k --trace &
# run (trial)
./test-httpserver2 -r -k --trace -T &

# chrome or edge
#   https://localhost:9000/
#   https://[::1]:9000/
# curl
#   curl https://localhost:9000/ -v -s -k --http2
#   curl https://[::1]:9000/ -v -s -k --http2

# stop
rm .run
```

- [x] tasks
  - [x] network_server
  - [x] HTTP/2
  - [x] libssl
  - [x] trial
  - [x] ALPN

#### related implementation

* [sdk/net/http](../../../sdk/net/http/README.md)
* [sdk/net/tls](../../../sdk/net/tls/README.md)

#### test sources

* `run_server.cpp`
* `sample.cpp`
* `sample.hpp`

#### test data / build files

* `CMakeLists.txt`
* `index.html`
* `pcap/` — captured HTTP/2 verification cases

`CMakeLists.txt` builds the applet with `maketest` and copies `index.html` into the build directory.


## What this applet demonstrates

The checked task list identifies the intended integration points: `network_server`, HTTP/2, both the libssl and trial paths, and ALPN. The documented browser/curl commands exercise HTTPS on both IPv4 localhost and IPv6 loopback and explicitly request HTTP/2 with curl.

The `pcap/` directory contains captured verification cases. These captures complement the runnable applet; they do not by themselves prove compatibility with every browser, HTTP/2 feature, or TLS configuration.
