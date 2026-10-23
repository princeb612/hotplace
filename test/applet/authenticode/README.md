# Authenticode Verification Applet

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

## 1. Role

This directory contains a small executable applet for exercising the Authenticode verifier against a caller-supplied file. It is not a dedicated `test/testcase/crypto/authenticode/` unit-test directory.

## 2. Integration Model

The sample expects a target file path, opens an `authenticode_verifier` context, enables CRL downloading for the sample, registers `trust.crt` as trusted root material, invokes `verify()`, and closes the context. The target file and trust certificate must be available in the runtime environment.

### Target executable path examples

The path syntax depends on where the command is entered. In particular, a MinGW executable launched from a shell and the same executable launched through MinGW GDB may use different path styles.

**1. Linux-style paths**

MinGW shell:

```sh
$ ./test-authenticate -v -i /c/home/tools/tool.exe
```

Linux shell:

```sh
$ ./test-authenticate -v -i ~/tools/tool.exe
```

**2. Windows-style paths**

MinGW GDB:

```text
$ gdb ./test-authenticate
(gdb) r -v -i c:\home\tools\tool.exe
```

Windows command prompt:

```bat
dir> test-authenticate -v -i c:\home\tools\tool.exe
```

Use the path form appropriate to the environment that parses the command; these examples refer to the target file passed through `-i`, not the path to `test-authenticate`.

```text
target PE file + trust.crt
          ↓
 verifier context + trust configuration
          ↓
 authenticode_verifier::verify()
          ↓
 return code / testcase report
```

Implementation entry points:

- `sample.cpp` — command-line setup, verifier/context lifecycle, trust-certificate registration, and result reporting.
- `sample.hpp` — applet declarations and included module setup.
- `CMakeLists.txt` — builds the `authenticode` applet target through the repository's `maketest` helper.

## 3. Interoperability

Interoperability with a network peer is not applicable to this applet. Its inputs are a target file and trust-certificate material; verification behavior also depends on certificate-chain and revocation data available in the runtime environment.

This is source-level documentation only. The applet was not executed during this documentation pass, and no applet-specific report was supplied as evidence. Do not infer a passing Authenticode applet result from aggregate crypto testcase totals.

## 4. Relationships

- [`sdk/crypto/authenticode`](../../../sdk/crypto/authenticode/) — implementation being exercised.
- [Authenticode verifier notes](../../../sdk/crypto/authenticode/authenticode_verifier.md) — verification stages and trust/CRL caveats.
