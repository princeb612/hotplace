## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace SDK                                 │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — SDK structure, implementation & behavior   │
└──────────────────────────────────────────────┘
```

# SDK

## 1. Role

The `sdk/` tree contains hotplace's reusable C++ library code. It is organized by responsibility, from foundational utilities and data representation through cryptographic operations and network protocols, with an optional ODBC integration layer.

The SDK is a set of cooperating modules rather than one mandatory runtime pipeline. Each module has its own data model and behavior; applications and applets compose only the parts they need. The module-level documents describe concrete types, implementation flow, and boundaries in more detail.

The project primarily targets C++11 and older supported toolchains. C++14-specific experiments are isolated rather than defining the baseline for the whole SDK.

## 2. Data Model

### Module map

| Module | Main responsibility | Primary boundary |
|---|---|---|
| [`base/`](base/README.md) | Common types and errors, byte/value utilities, encoding, in-memory streams and strings, containers, algorithms, graph structures, system helpers, and test infrastructure | General-purpose primitives; no protocol-specific semantics |
| [`io/`](io/README.md) | Binary payload layouts, file and OS I/O, string/URL handling, parsing, CBOR, and ASN.1 | Representation, syntax, and I/O boundaries |
| [`crypto/`](crypto/README.md) | Cryptographic primitives and keys, algorithm metadata, JOSE/COSE processing, Authenticode verification, and provider integration | Cryptographic operations and format-specific security processing |
| [`net/`](net/README.md) | Socket backends, server/session coordination, TLS/DTLS/QUIC, and HTTP protocols | Transport and protocol state |
| [`odbc/`](odbc/README.md) | Thin wrappers over native ODBC environment, connection, statement, and result APIs | Optional database connectivity; enabled by `SUPPORT_ODBC` |

The top-level module directories are also the main source-document entry points. Their READMEs describe each module's data and behavior; deeper documents focus on individual subsystems.

### Public header entry points

The SDK provides umbrella headers that collect headers from related modules:

| Header | Purpose |
|---|---|
| [`sdk/sdk.hpp`](sdk.hpp) | Includes the common Base, Crypto, I/O, and Network entry points |
| [`sdk/base.hpp`](base.hpp) | Common definitions and general-purpose facilities |
| [`sdk/io.hpp`](io.hpp) | I/O, parsing, CBOR, and ASN.1 facilities |
| [`sdk/crypto.hpp`](crypto.hpp) | Cryptographic operations, keys, JOSE/COSE, and Authenticode |
| [`sdk/net.hpp`](net.hpp) | Network transports, server facilities, TLS/DTLS/QUIC, and HTTP |
| [`sdk/odbc.hpp`](odbc.hpp) | ODBC wrappers when that optional module is enabled |
| [`sdk/oqs.hpp`](oqs.hpp) | OQS provider-facing integration declarations |

An umbrella header is an inclusion convenience, not a statement that every included feature is always available on every platform or build configuration. In particular, ODBC is conditionally built, and platform/provider-specific facilities retain their own prerequisites.

## 3. Behavior Model

### Cross-module flow

```text
                    Application / applet
                            |
              chooses and composes facilities
                            |
           +----------------+----------------+
           |                |                |
           v                v                v
      sdk/base          sdk/io           sdk/crypto
  common primitives   representation,    crypto operations,
  and data structures parsing, formats   keys, security formats
           |                |                |
           +----------------+----------------+
                            |
                            v
                         sdk/net
              transport and protocol behavior
                            |
                            v
                  peer / application data

      sdk/odbc is a separate optional path to native ODBC APIs
```

This is a responsibility map, not a strict dependency graph or execution sequence. For example, `sdk/crypto` uses common representations and I/O formats, while `sdk/net` composes cryptographic operations into transport protocols. A particular application need not traverse every module.

### Build composition

The SDK's `CMakeLists.txt` adds `base`, `io`, `crypto`, and `net` as subdirectories. It adds `odbc` only when `SUPPORT_ODBC` is enabled. The repository-level build scripts and root CMake configuration control the overall build and test workflow; this directory participates in that workflow rather than defining a separate standalone build process.

## 4. Relationships

- **Base → I/O:** I/O facilities use shared types, byte/value helpers, and stream abstractions, while defining their own parsing and representation models.
- **Base and I/O → Crypto:** cryptographic formats and key operations build on common utilities and representations; cryptographic policy and protocol-specific sequencing remain with their respective consumers.
- **Crypto → Network:** TLS/DTLS/QUIC use cryptographic primitives, key abstractions, and algorithm metadata, while handshake state, record/packet processing, and transport behavior belong to `sdk/net`.
- **I/O and Crypto → Network protocols:** parsing and encoded representations support protocol messages, but the presence of a parser or encoder alone does not imply full protocol validation or conformance.
- **ODBC alongside the core modules:** ODBC is an optional integration boundary and is not a prerequisite for Base, I/O, Crypto, or Network.

