# test/testcase

`test/testcase` is the automated verification layer for the SDK. Test groups are organized primarily by the feature/protocol boundary they verify, and each group is built as a `test-<module>` executable.

## Test groups

| Group | Role |
|---|---|
| `base` | common containers, utilities, strings, system facilities and unittest infrastructure |
| `encode` | encoding/decoding facilities |
| `io` | I/O and parser/system functionality |
| `cbor` | CBOR encoding/decoding and RFC examples |
| `asn.1` | ASN.1 parsing, construction, encoding/decoding and constraints |
| `crypto` | cryptographic primitives, keys, KDF, signatures, PQC and related backends |
| `jose` | JOSE/JWK/JWS/JWE behavior and RFC examples |
| `cose` | COSE/CBOR cryptographic processing and RFC examples |
| `net` | network/basic HTTP support and protocol components |
| `tls` | TLS/DTLS behavior and packet/handshake test material |
| `quic` | QUIC packet/session/HTTP3-related verification |
| `odbc` | ODBC integration |
| `linux` | Linux-specific behavior |
| `windows` | Windows-specific behavior |

The exact source/testcase layout can evolve independently of the SDK source tree; the stable meaning is the verification boundary represented by each group.

## Build and CTest flow

`test/testcase/CMakeLists.txt` adds the testcase groups and copies `test.sh` into the build tree. At the project level, the root `maketest()` helper creates each `test-<module>` executable and registers it with CTest when that target is configured for CTest.

```text
CMake configure/build
        │
        ▼
 test/testcase/CMakeLists.txt
        │
        ├── base / encode
        ├── io / cbor / asn.1
        ├── crypto / jose / cose
        ├── net / tls / quic
        ├── odbc (when SUPPORT_ODBC)
        └── linux or windows
                 │
                 ▼
          test-<module>
                 │
                 └── CTest registration
```

CTest is the normal automated test entry point in the MinGW64/GCC development environment and the MSVC/Windows environment. It is also used on the CentOS 7 Sanitizer environment.

## Environment-specific verification

The repository deliberately uses different diagnostic layers for different environments:

| Environment | Primary execution | Additional verification |
|---|---|---|
| MinGW64 / GCC | `ctest` | Application Verifier |
| CentOS 7 | `ctest` | Sanitizer |
| Ubuntu 20 | `test.sh` | Valgrind: `memcheck`, `helgrind`, `drd` |
| Windows / MSVC | `ctest` | Application Verifier |

This is part of the project's compatibility/verification strategy rather than four equivalent ways of launching the same script. In particular, Ubuntu 20 is the environment where the repository's `test.sh` + Valgrind pass is used.

## Running `test.sh`

From the built `test/testcase` directory:

```bash
./test.sh
```

runs the groups selected by the script. A single group can be selected:

```bash
./test.sh base
./test.sh crypto
./test.sh tls
```

The current default script selection is:

```text
base encode
  io cbor asn.1
  crypto cose jose
  net tls quic
  windows   # on Cygwin/MSYS
  linux     # otherwise
```

ODBC is present in the CMake testcase graph when `SUPPORT_ODBC` is enabled, but it is **not included in the current no-argument `test.sh` array**. That distinction should be preserved when interpreting test coverage.

## Valgrind diagnostic pass

When Valgrind is available, `test.sh` runs each selected executable through:

- `memcheck` — memory/leak/origin checking
- `helgrind` — thread synchronization checking
- `drd` — thread error checking

The reports are written as `report-memcheck`, `report-helgrind`, and `report-drd` in the corresponding build directory. This pass is the Ubuntu 20 verification path; it is not the general CTest mechanism.

Some runnable network applets are intentionally excluded from the automatic `test.sh` pass because they require user interaction or external peers. Those belong under `test/applet`.

## Test material and references

The testcase tree also preserves protocol-specific evidence and study material: RFC vectors, packet captures, TLS flow notes, cryptographic test vectors, schemas, and platform-specific investigation notes. These documents are part of the test history and should not be reduced to generic test descriptions.

## Related areas

- [`test`](../README.md) — overall test-area structure
- [`applet`](../applet/README.md) — runnable integration/example programs
- [`tool`](../tool/README.md) — test-supporting tools
- `sdk/base`, `sdk/io`, `sdk/crypto`, `sdk/net`, `sdk/odbc` — implementation areas verified here
