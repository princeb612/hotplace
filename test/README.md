# test

`test` is hotplace's verification and runnable-example area. It is not a single test framework; it contains three different kinds of executable material:

```text
test/
├── testcase/       SDK feature / protocol verification
├── applet/         runnable integration / server / client examples
└── tool/           test-supporting generation tools
```


## Verification environments

The test area is exercised differently depending on the target development and verification environment. `ctest`, Sanitizer, Valgrind, and Application Verifier are complementary rather than interchangeable test entry points.

```text
hotplace verification
│
├─ MinGW64 / GCC
│    └─ ctest + Application Verifier
│
├─ CentOS 7
│    └─ Sanitizer + ctest
│
├─ Ubuntu 20
│    └─ test.sh
│         └─ Valgrind
│              ├─ memcheck
│              ├─ helgrind
│              └─ drd
│
└─ Windows / MSVC
     └─ ctest + Application Verifier
```

The distinction matters when reading historical test records: a testcase being registered with CTest does not mean that every environment runs it through the same diagnostic tool. The environment determines the additional runtime verification pass.

## testcase

`test/testcase` contains the ordinary automated test executables. The directory follows the SDK and protocol structure rather than mirroring every source directory:

```text
base / encode
      ↓
io / cbor / asn.1
      ↓
crypto / jose / cose
      ↓
net / tls / quic
      ↓
odbc
      ↓
linux / windows
```

The corresponding `CMakeLists.txt` builds these groups and conditionally includes ODBC and platform-specific tests.

Each group normally produces a `test-<module>` executable. The copied `testcase/test.sh` can execute one group or the complete automated set.

## applet

`test/applet` contains runnable programs that exercise the SDK as actual applications rather than isolated testcase functions. Examples include TCP/UDP servers, TLS/DTLS servers, HTTP/1.1 and HTTP/2 servers, a network client, and the Windows Authenticode verifier.

Some applets require external interaction or runtime data such as HTML/CSS or packet captures, so they are intentionally separate from the ordinary automated testcase pass.

## tool

`test/tool` contains utilities used to prepare test resources. The current important tool is `makeparsingtable`, which generates the parser table resources used by parser-related tests.

## Build relationship

```text
root CMakeLists.txt
       │
       ▼
     test/
   ┌───┼────┐
   ▼   ▼    ▼
testcase applet tool
   │          │
   │          └─ parsing table generation
   │
   └─ test executables
```

The normal project build therefore owns test target creation, while `testcase/test.sh` provides the runtime execution/diagnostic layer.

## Related documentation

- [testcase](testcase/README.md)
- [applet](applet/README.md)
- [tool](tool/README.md)
