## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: runnable integration/example programs
```

# Test applets

## 1. Role

`test/applet` contains runnable programs that exercise the SDK as applications or network peers rather than as isolated testcase functions. Some applets require external interaction, local certificate material, HTML/CSS assets, or packet captures.

## 2. Model

| Applet | Purpose |
|---|---|
| `authenticode/` | Windows PE Authenticode verification |
| `dtlsserver/` | DTLS 1.2 server |
| `httpserver1/` | HTTP/1.1 server |
| `httpserver2/` | HTTP/2 server |
| `netclient/` | TCP/UDP/TLS/DTLS client |
| `tcpserver1/`, `udpserver1/` | Multiplexer-integrated TCP/UDP servers |
| `tcpserver2/`, `udpserver2/` | `network_server`-integrated TCP/UDP servers |
| `tlsserver/` | TLS 1.2/1.3 server |

## 3. Example from the build

The applet directory is included from `test/applet/CMakeLists.txt`. Each applet has its own `CMakeLists.txt` and uses the project `maketest` helper to build its executable from local source files. Runtime resources are documented in the corresponding applet README and may be copied from `etc/cert/` during build setup.

## 4. Test and verification status

### 4.1 Source-level coverage

An applet is an integration/example program, not automatically an automated testcase. Interactive clients, servers and external-peer flows may not be included in the ordinary `ctest` or `test.sh` pass.

### 4.2 Documentation and verification status

The directory inventory does not claim that all applets were launched or that a peer/certificate configuration was available.

## 5. Relationships

- `test/testcase/` — automated testcase executables.
- `test/tool/` — test-supporting generation tools.
- `etc/cert/` — certificate/key fixtures distributed into build-tree applet directories.
- `sdk/net/` and `sdk/crypto/` — implementations exercised by network and Authenticode applets.

## 6. References

- [Overall test area](../README.md)
- `test/applet/CMakeLists.txt`
- [Certificate fixture distribution](../../etc/cert/README.md)
