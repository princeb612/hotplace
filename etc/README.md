## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: repository-managed resources and environment helpers
```

# Repository resources

## 1. Role

The `etc/` directory contains repository-managed resources used by hotplace's build, test, and development workflows. It is part of the source tree, not the operating system's `/etc` directory.

Its contents have different forms but share one responsibility: provide inputs or helpers consumed by the project rather than implement SDK runtime behavior.

## 2. Data Model

```text
etc/
├─ cert/
│  ├─ trust/trust.crt
│  ├─ server-*.crt / server-*.key
│  ├─ server-*.der                 (optional fixture input)
│  ├─ issue.sh / crt2der.sh
│  └─ CMakeLists.txt
├─ parsingtable/
│  ├─ parsingtable.zip
│  └─ CMakeLists.txt
└─ script/
   ├─ env.mingw64
   ├─ env.rockylinux
   └─ env.ubuntu
```

- `cert/` contains a checked-in trust bundle, generated certificate/key fixtures, and scripts for generating or converting test certificates.
- `parsingtable/` contains the packaged binary parser-table archive. The grammar and table-generation utility are maintained elsewhere in the source tree.
- `script/` contains shell files defining environment-specific helper functions. They are intended to be sourced by a developer's shell, not executed as standalone applications.

The directory therefore combines certificate data, a generated binary artifact, and executable shell definitions; their individual data models are documented in their subdirectory READMEs.

## 3. Behavior Model

```text
Certificate fixtures
  issue.sh / crt2der.sh
       │ generate / convert
       ▼
  etc/cert files ── CMake copy ──► build-tree test fixtures

Parser tables
  grammar + makeparsingtable
       │ generate (.ptb)
       ▼
  parsingtable.zip ── unzip ─────► build-tree parser / ASN.1 resources

Environment helpers
  source etc/script/env.<environment>
       │
       ├─ install_packages()
       ├─ export_path()
       └─ environment-specific helpers
```

Certificate generation and DER conversion are separate operations. Generating root/server fixtures does not update `trust/trust.crt`. The certificate CMake rules copy matching repository inputs into configured build-tree locations.

Parser-table generation and archive extraction are also separate. The generator's post-build packaging path is conditional (GNU compiler on Windows, used for the documented MinGW64 path); `etc/parsingtable/CMakeLists.txt` extracts the existing archive and does not regenerate the tables.

Environment scripts define different functions according to platform. They are sourced into the current shell so their functions and environment changes are available to subsequent commands. Package installation, library search-path setup, and runtime DLL redistribution are environment-specific operations, not replacements for root `make.sh` or CMake orchestration.

## 4. Relationships

- [Certificate fixtures](cert/README.md) — certificate and key files, generation/conversion scripts, and build-tree destinations.
- [Binary parsing tables](parsingtable/README.md) — table archive and extraction behavior.
- [Environment scripts](script/README.md) — available helper functions by environment.
- `sdk/io/parser/` and `sdk/io/asn.1/` — parser runtime and ASN.1 consumers of table artifacts.
- `sdk/net/tls/` and `sdk/net/http/` — secure transport/server paths using certificate fixtures.
- `sdk/crypto/authenticode/` — trust bundle consumer.
- `test/tool/makeparsingtable/` — table generator.
- `test/applet/` and `test/testcase/` — consumers of resources copied or unpacked into the build tree.
- Root `make.sh` and CMake configuration — build orchestration.
