# Multiplexer-integrated TCP server applet

`tcpserver1` is the first runnable TCP server in the repository's progression toward TLS and HTTP server applets. Its `run_server.cpp` works directly with the multiplexer/socket event path; `sample.cpp` contains shared applet setup.

## Build and sources

- Sources: `run_server.cpp`, `sample.cpp`
- Build definition: `CMakeLists.txt`

The source comments place this applet before `tcpserver2`, `tlsserver`, `httpserver1`, and `httpserver2` as a learning sequence. It is a demonstration of event-driven TCP handling, not an HTTP or TLS server.
