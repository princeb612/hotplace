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
