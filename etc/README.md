## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: repository-managed resources and build/test distribution
```

# Repository resources

## 1. Role

The `etc/` area contains repository-managed resources consumed by the build and test infrastructure. It is part of the hotplace source tree, not the operating system's `/etc` directory. The main documented resource groups are certificate fixtures and binary parser tables.

## 2. Model

```text
etc/
├─ cert/
│  ├─ trust/trust.crt
│  ├─ server-*.crt / server-*.key / server-*.der
│  ├─ issue.sh
│  ├─ crt2der.sh
│  └─ CMakeLists.txt
└─ parsingtable/
   ├─ parsingtable.zip
   └─ CMakeLists.txt
```

The resource groups have separate lifecycles:

- `cert/` contains test certificate/key fixtures and scripts to regenerate or convert them.
- `parsingtable/` contains generated binary parser tables; the grammar/generator source is maintained under `test/tool/makeparsingtable`, not as hand-edited binary content.

## 3. Important behavior and lifetime

### Certificate distribution

`etc/cert/CMakeLists.txt` copies the trust certificate and server certificate/key fixtures into build-tree test and applet directories. DER certificate fixtures are copied to ASN.1 testcase locations. The copies consumed by tests are build artifacts derived from the repository-managed files, not independent certificate sources.

### Parsing-table distribution

`test/tool/makeparsingtable` generates LALR(1) and GLR table files. Its CMake post-build generation path is guarded for GNU on Windows (MinGW64); `etc/parsingtable/CMakeLists.txt` unpacks the stored `parsingtable.zip` into the build-tree parser and ASN.1 testcase directories. Check the active build setup before assuming manual unpacking is required.

## 4. Example from the source build

A typical resource flow is:

```text
repository-managed resource
       │
       ├── etc/cert/ ── CMake copy ──► build-tree certificate fixtures
       │
       └── etc/parsingtable/ ─ unzip ─► parser / ASN.1 testcase tables

grammar + makeparsingtable tool
       └── generated .ptb files ──► parsingtable.zip (configured build path)
```

This describes the configured build flow, not a claim that every target has regenerated the tables or executed all consumers.

## 5. Relationships

- `sdk/io/parser/` — parser runtime and binary parsing-table format.
- `sdk/io/asn.1/` — ASN.1 parser/runtime consuming grammar tables and DER certificate test data.
- `sdk/net/tls/` and `sdk/net/http/` — certificate fixtures used by secure transport/server test paths.
- `sdk/crypto/authenticode/` — trust certificate and PE verification example.
- `test/tool/makeparsingtable/` — parser table generator.
- `test/applet/` and `test/testcase/` — consumers of copied resources.

## 6. References

- [Certificate fixtures](cert/README.md)
- [Certificate generation options](cert/help.md)
- [Binary parsing tables](parsingtable/README.md)
- `etc/cert/CMakeLists.txt`
- `etc/parsingtable/CMakeLists.txt`
- `test/tool/makeparsingtable/CMakeLists.txt`
