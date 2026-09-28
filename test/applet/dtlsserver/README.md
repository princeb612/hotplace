#### test

* DTLS 1.2
  * ./test-tlsserver.exe -r -k --trace &

* stop server
  * rm .run

#### related implementation

* [sdk/net/tls](../../../sdk/net/tls/README.md)

#### test sources

* `run_server.cpp`
* `sample.cpp`
* `sample.hpp`

#### test data / build files

* `CMakeLists.txt`

The applet is a runnable DTLS 1.2 server used by the network test flow.
