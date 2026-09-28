#### applets

- [authenticode](authenticode/README.md)
  - Windows executable file Authenticode verification
- [dtlsserver](dtlsserver/README.md)
  - DTLS 1.2 server
- [httpserver1](httpserver1/README.md)
  - HTTP/1.1 server
- [httpserver2](httpserver2/README.md)
  - HTTP/2 server
- [netclient](netclient/README.md)
  - TCP/UDP/TLS/DTLS client
- [tcpserver1](tcpserver1/README.md)
  - multiplexer-integrated TCP server
- [tcpserver2](tcpserver2/README.md)
  - network-server-integrated TCP server
- [tlsserver](tlsserver/README.md)
  - TLS 1.2/1.3 server
- [udpserver1](udpserver1/README.md)
  - multiplexer-integrated UDP server
- [udpserver2](udpserver2/README.md)
  - network-server-integrated UDP server

#### build

The applet directory is included from `test/applet/CMakeLists.txt`. Each applet has its own `CMakeLists.txt` and uses `maketest` to build the executable from its local `*.cpp` / `*.hpp` sources.

Some applets also contain runtime data such as HTML/CSS files or packet captures; those are documented in the corresponding applet README.
