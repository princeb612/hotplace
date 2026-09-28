# Build

## Context

hotplace's build system is distributed across shell scripts and CMake files, but the structure has two distinct stages:

```text
thirdparty build
      ↓
dependency installation
      ↓
hotplace build
      ↓
libraries / tests / applets
```

The two principal hotplace entry points are:

- `make.sh` — configures and builds hotplace itself.
- top-level `CMakeLists.txt` — constructs the hotplace target graph.

The third-party stage has its own entry point:

- `thirdparty/make.sh` — downloads, extracts, builds, and installs selected external libraries.

This separation is important: **the root `make.sh` does not automatically build `thirdparty` dependencies.** The dependency preparation is a preceding, independently controlled stage.

## History

The build system has evolved together with the project's platform and protocol coverage. The recorded source history and build notes show Linux, MINGW64, MSVC, static/shared builds, older GCC compatibility, and manual dependency preparation.

The third-party layer is therefore not simply a list of libraries. It records version selection, package-specific build procedures, compiler-family-specific installation areas, and compatibility workarounds.

The old-platform notes are especially revealing:

```text
old environment
    ↓
upgrade Bash
    ↓
upgrade CMake
    ↓
build dependencies
    ↓
build hotplace
```

The project treats the build environment itself as something that may need to be reconstructed.

## Conceptual

The build model is best understood as three boundaries.

```text
                dependency source
                       │
                       ▼
              thirdparty build
                       │
                       ▼
          compiler-specific install
                       │
                       ▼
              project CMake model
                       │
                       ▼
             hotplace target graph
                       │
              ┌────────┴────────┐
              ▼                 ▼
          libraries          tests/applets
```

### Dependency build

`thirdparty/make.sh` answers:

> Which external packages should be built, with which compiler family/configuration, and where should they be installed?

### Project configuration

Root `make.sh` answers:

> With which compiler, flags, feature switches, and build mode should hotplace itself be configured?

### Target graph

Top-level `CMakeLists.txt` answers:

> Which hotplace targets exist, how do SDK modules depend on one another, and which external/platform libraries do they link?

This gives a clean division:

```text
thirdparty/make.sh
    = dependency acquisition/build

root make.sh
    = project build policy/orchestration

CMakeLists.txt
    = project target graph
```

## Structural

### `thirdparty/dependency`

The dependency file separates **package selection** from **package build mechanics**.

Each declaration carries the conceptual fields:

```text
name
url
dir
build
buildscript
```

The current active set is:

```text
OpenSSL 4.0.2
Jansson 2.15.0
zlib 1.3.2
yaml-cpp 0.9.0
```

Optional declarations include:

```text
liboqs 0.15.0
oqs-provider 0.10.0
```

The file also retains alternative OpenSSL versions and an older yaml-cpp version for older GCC environments.

This is useful historically: the dependency file is both a **current selection** and a record of build alternatives that have mattered to the project.

### `thirdparty/function`

The function file adapts different upstream build systems to one local orchestration model.

```text
download / inflate
        │
        ├── build_openssl
        ├── build_jansson
        ├── build_cmake
        └── build_oqsprovider
```

The distinction is significant.

OpenSSL has its own `Configure`/Make flow:

```text
OpenSSL source
    ↓
./Configure
    ↓
make
    ↓
install_sw / install_ssldirs
```

Jansson uses CMake:

```text
Jansson source
    ↓
cmake
    ↓
make
    ↓
make install
```

zlib and yaml-cpp use the common CMake adapter:

```text
source
    ↓
build_cmake()
    ↓
cmake / make / make install
```

`oqs-provider` has its own function because its CMake configuration needs additional project-specific options.

Thus `thirdparty/function` is an **upstream-build adapter layer**.

### `thirdparty/make.sh`

The third-party orchestrator selects:

```text
base
  ├── gcc
  └── msvc

generator
  ├── Unix Makefiles
  └── Visual Studio 18 2026

target
  ├── Release
  └── Debug
```

It then processes the selected dependency array:

```text
dependency
    ↓
download if absent
    ↓
extract if absent
    ↓
select build function
    ↓
build/install
    ↓
touch .complete
```

The installation root is:

```text
thirdparty/gcc
thirdparty/msvc
```

and is selected by the `base` value.

The script also sets:

```text
MAKEFLAGS='-j 4'
```

for the dependency build.

### `.complete` as build state

The package build state is intentionally simple:

```text
package source directory
        │
        ├── .complete exists
        │       └── skip
        │
        └── no .complete
                └── build/install
```

The marker is created only after the package's installation sequence completes.

This is not a general package manager or dependency resolver. It is a local mechanism for making the project's controlled dependency build repeatable enough for its intended environments.

### Compiler-family installation boundary

Third-party artifacts are separated by compiler family:

```text
thirdparty/
├── gcc/
│   ├── include/
│   ├── lib/
│   └── lib64/
│
└── msvc/
    ├── include/
    └── lib/
```

The project CMake selects the corresponding directory:

```text
GNU
    → thirdparty/gcc

MSVC
    → thirdparty/msvc
```

The CMake layer then exposes the selected installation through:

```text
include_directories(...)
link_directories(...)
```

This is the key physical hand-off between the two build stages.

### OpenSSL as the representative dependency

OpenSSL is the most informative example because its build configuration depends on the host environment.

For GCC/Linux:

```text
./Configure linux-x86_64
        ↓
make
        ↓
install_sw install_ssldirs
```

For Cygwin/MSYS:

```text
./Configure mingw64
        ↓
make
        ↓
install
```

For MSVC, the function does not try to hide the upstream requirements. It gives the operator a manual sequence involving:

```text
Visual Studio
Perl
vcvars64.bat
perl Configure VC-WIN64A
nmake
nmake install_sw install_ssldirs
```

This is a useful design characteristic: **the third-party abstraction does not pretend that every upstream build can be normalized to the same command sequence.**

### Version as capability

The OpenSSL version selection is tied to project capabilities.

The third-party README records, for example:

```text
OpenSSL 1.1.1+
    RSA-OAEP-256
    Ed25519 / Ed448
    X25519 / X448
    SHA-3

OpenSSL 3.0 / 3.1
    provider/fetch APIs
    truncated SHA variants

OpenSSL 3.2
    Argon2 variants

OpenSSL 3.5
    ML-KEM
    ML-DSA
```

This means dependency version is not merely maintenance metadata:

```text
OpenSSL version
      ↓
available external API/algorithm capability
      ↓
sdk/crypto
      ↓
TLS / QUIC / JOSE / COSE features
```

PQC is the clearest example.

### Optional PQC dependency

The optional path is:

```text
SUPPORT_OQS
    │
    ├── liboqs
    │
    └── oqs-provider
             │
             ▼
          OpenSSL 3.x
```

The dependency build supplies the external implementation/provider. The hotplace crypto layer remains the project's own abstraction and integration boundary.

Therefore:

```text
thirdparty
    = external implementation supply

sdk/crypto
    = hotplace cryptographic abstraction/integration
```

These should not be documented as the same layer.

### yaml-cpp as a compatibility example

yaml-cpp exposes another aspect of the design.

The dependency file retains:

```text
yaml-cpp 0.6.3
```

for older GCC environments, while the active dependency uses:

```text
yaml-cpp 0.9.0
```

The source comments explicitly distinguish the library naming behavior:

```text
older GCC
    release → libyaml-cpp.a
    debug   → libyaml-cpp.a

newer GCC
    release → libyaml-cpp.a
    debug   → libyaml-cppd.a
```

The top-level CMake therefore cannot treat Debug/Release dependency names as universally identical.

This is a concrete example of why the third-party layer and the project CMake layer have to agree on:

```text
compiler
+
configuration
+
dependency version
+
library filename
```

### Root `make.sh`

The root script controls project-side policy.

Representative switches include:

```text
cmake
debug
ctest
test
pch
static/shared
disable_static
odbc
oqs
sanitize
prof
opt
toolchain
verbose
msvc
redist
```

These fall into different categories:

```text
configuration
    debug / pch / static / shared / oqs / odbc
        │
        ▼
environment variables / compiler flags
        │
        ▼
CMake

build action
    cmake / ctest / test

environment/toolchain
    msvc / toolchain / redist
```

The distinction matters because the script is not simply a wrapper around `cmake --build`; it is the project's **build-policy dispatcher**.

### Root `CMakeLists.txt`

The top-level CMake consumes the environment established by `make.sh`.

Important inputs include:

```text
CXXFLAGS
CMAKE_CXX_COMPILER
SUPPORT_DEBUG
SUPPORT_STATIC
SUPPORT_SHARED
SUPPORT_ODBC
SUPPORT_PCH
SUPPORT_OQS
SET_STDCPP
```

It then determines:

```text
compiler
    ↓
thirdparty root
    ↓
thirdparty library names
    ↓
platform libraries
    ↓
hotplace module graph
```

The current compiler boundary is:

```text
GNU
    → thirdparty/gcc

MSVC
    → thirdparty/msvc
```

The third-party libraries are combined with platform dependencies such as:

```text
UNIX
    dl
    pthread

Windows
    ws2_32
```

and, where applicable:

```text
pcre
odbc
```

### Project target helpers

Once the external libraries are selected, three project-specific functions become the target-construction boundary:

```text
makelib
makelibdep
maketest
```

Conceptually:

```text
source group
    +
module dependency
    +
thirdparty/platform libraries
        │
        ▼
hotplace target
```

`makelibdep` additionally establishes target dependency ordering.

This is why the many child CMake files do not need to independently implement the whole build policy.

### SDK dependency graph

The current SDK build model is:

```text
sdk-base
    ↓
sdk-io
    ↓
sdk-crypto
    ↓
sdk-net
```

with optional:

```text
sdk-odbc
```

The external dependency set is supplied alongside this graph rather than being part of the SDK module dependency hierarchy itself.

That distinction is useful:

```text
hotplace module dependency
    base → io → crypto → net

external library dependency
    OpenSSL / Jansson / zlib / yaml-cpp / ...

platform dependency
    pthread / dl / ws2_32 / pcre / odbc / ...
```

## Flow

### Fresh dependency preparation

```text
thirdparty/make.sh
        │
        ▼
select gcc/msvc
        │
        ▼
select Release/Debug
        │
        ▼
read dependency array
        │
        ▼
download
        │
        ▼
extract
        │
        ▼
package-specific builder
        │
        ▼
install into thirdparty/<compiler>
        │
        ▼
.complete
```

### Project build

```text
./make.sh [options]
        │
        ▼
select compiler / flags / features
        │
        ▼
cmake -B build
        │
        ▼
top-level CMakeLists.txt
        │
        ├── compiler detection
        ├── thirdparty root
        ├── library names
        ├── platform dependencies
        ├── makelib*
        └── subdirectories
        │
        ▼
cmake --build
        │
        ▼
SDK libraries
        │
        ├── testcase
        └── applet
```

### Important non-flow

There is deliberately **no automatic path** in the root build equivalent to:

```text
./make.sh
   ↓
thirdparty/make.sh
   ↓
build dependencies
```

Instead, the intended conceptual sequence is:

```text
prepare dependency environment
        ↓
thirdparty/make.sh
        ↓
build hotplace
        ↓
./make.sh
```

This separation lets the same hotplace source tree consume:

```text
thirdparty/gcc
thirdparty/msvc
thirdparty/toolchain
```

without making every project build automatically rebuild external sources.

## Study & Verification

The build system itself is a compatibility study surface.

The source documents concerns involving:

- older GCC versions
- older Linux distributions
- MINGW64
- MSVC
- static/shared builds
- precompiled headers
- sanitizer builds
- ODBC
- OQS/PQC
- custom toolchains
- old Bash versions
- old CMake versions

The old-platform notes are particularly useful because they expose why the build system has accumulated explicit compatibility branches.

For example:

```text
CMake 2.8
   ↓
3.1
   ↓
3.10
   ↓
3.12
   ↓
3.13
   ↓
3.16
```

is not a claim that all those versions remain the current supported matrix. It is evidence of the effort required to establish a sufficiently capable build environment on older systems.

Similarly, the compiler check:

```text
GNU < 4.9
    ↓
PROJECT_SDK_USE_STD_REGEX = 0
    ↓
PCRE path
```

shows that source-level portability and dependency-level portability are connected.

## Status

At Revision 1090:

- `thirdparty/make.sh` is the external dependency build entry point.
- `thirdparty/dependency` defines the active and retained dependency package selections.
- `thirdparty/function` adapts package-specific upstream build procedures.
- `.complete` provides a local dependency-build completion state.
- compiler-family-specific installation roots are used for GCC and MSVC.
- root `make.sh` independently controls the hotplace build.
- top-level `CMakeLists.txt` consumes the selected third-party installation and constructs the hotplace target graph.
- OpenSSL version selection is materially connected to cryptographic capability.
- yaml-cpp demonstrates compiler/version/configuration-specific library naming.
- liboqs and oqs-provider form an optional external PQC path.
- custom `thirdparty/toolchain` support provides another build-environment boundary.

At this point, the important structure of the build system is sufficiently captured without documenting every individual child `CMakeLists.txt`.

A deeper pass would mainly become **file-by-file inventory**, rather than adding a new architectural concept.

## Related topics

- [Base](../base/README.md)
- [Crypto](../crypto/README.md)
- [TLS](../tls/README.md)
- [Network Server](../network_server/README.md)
- [Parser](../io/parser/README.md)
