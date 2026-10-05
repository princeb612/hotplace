# etc

The `etc/` area contains repository-managed resources that are consumed by the build and test infrastructure. It is part of the hotplace source tree rather than a system `/etc` directory.

## Directory map

```text
etc/
├─ cert/
│  ├─ trust/          — trust certificate used by Authenticode tests
│  ├─ server-*.crt    — server certificate fixtures
│  ├─ server-*.key    — server private-key fixtures for test environments
│  ├─ issue.sh        — generate self-signed certificate sets
│  └─ crt2der.sh      — convert certificate files from CRT/PEM to DER
│
└─ parsingtable/
   ├─ parsingtable.zip — parser table resources
   └─ CMakeLists.txt   — copy/install the table resources for tests
```

## Resource flow

`etc/` resources are prepared at the project level and copied into the appropriate build/test locations by CMake. They are therefore part of the source-side test fixture and parser-resource chain.

```text
repository resources
       │
       ├───────────────┐
       ▼               ▼
     cert/       parsingtable/
       │               │
       ▼               ▼
 CMake copy       CMake copy
       │               │
       ▼               ▼
 test fixtures    parser test resources
```

### `cert/`

Certificate material is used by TLS, QUIC, DTLS, HTTP server, Authenticode, and ASN.1-related tests. `cert/CMakeLists.txt` copies the appropriate certificate/key or DER files into the corresponding build-time test directories.

The directory also contains scripts for generating self-signed certificate sets and converting certificates to DER for tests that consume binary certificate data.

### `parsingtable/`

Binary parsing-table resources are generated/maintained separately from the parser implementation and are copied into test locations during the build/test setup. See [`parsingtable/README.md`](parsingtable/README.md) for the current table variants and generation commands.

## Related areas

- `sdk/io/parser/` — parser runtime and binary parsing-table format
- `sdk/io/asn.1/` — ASN.1 parser and runtime consuming ASN.1 parsing tables and DER test data
- `sdk/net/tls/` — TLS certificate fixtures
- `sdk/net/quic/` — QUIC certificate fixtures
- `test/applet/` and `test/testcase/` — consumers of the resources copied from this directory

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```
