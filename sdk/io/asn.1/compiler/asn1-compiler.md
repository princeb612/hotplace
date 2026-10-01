# ASN.1 Compiler

## Role

The `sdk/io/asn.1/compiler` directory currently contains the **design/documentation stage of the ASN.1 compiler concept** rather than a completed compiler implementation.

There is no compiler implementation source in this directory at revision 1095. The main artifact is `compiler-flow.md`, which records an `asn1c`-style command-line and C++ source-generation design.

## Intended role

The planned compiler flow is:

```text
ASN.1 module
     |
     v
 parser
     |
     v
 syntax / semantic representation
     |
     v
 C++ type / codec generation
     |
     +---- header
     +---- source
     +---- build integration
```

The design describes generation of C++11 data structures, DER codec interfaces, constraint checks, and build files from an ASN.1 schema.

## Design documented in compiler-flow.md

The existing design sketch covers:

- `asn1c [options] <asn1_file...>` command-line form
- output directory and namespace options
- DER codec selection
- constraint-generation option
- verbose/help options
- generated header/source structure
- Makefile/CMake/nmake integration considerations
- ASN.1 tag to C++ type mapping
- AUTOMATIC / IMPLICIT / EXPLICIT tagging
- generated encode/decode and constraint-check interfaces
- an example `UserProfile.asn1` → C++ model

These are **design notes**, not evidence that the described command-line compiler and generated-code pipeline are already implemented in revision 1095.

## Relation to the current ASN.1 implementation

The compiler concept builds on functionality that already exists elsewhere:

```text
                 ASN.1 source
                      |
                      v
                  parser
                      |
                      v
             semantic construction
                      |
              +-------+-------+
              |               |
              v               v
        runtime schema    future compiler
              |               |
              v               v
        encode/decode     generated C++
```

The current runtime and parser should therefore be considered the implemented foundation; the compiler is a future generation layer over that foundation.

## Current status

**Design / study stage.**

The directory should not be documented as though `asn1c` is currently a usable compiler binary. The detailed flow document is valuable as a record of the intended architecture and can remain as a design artifact.

## Related source

- `sdk/io/asn.1/runtime/`
- `sdk/io/parser/`
- `sdk/io/asn.1/basic/`

There is currently no compiler `.cpp` implementation under `sdk/io/asn.1/compiler/`.

## Related tests and examples

The existing ASN.1 testcase tree demonstrates the parser, semantic construction, runtime, and DER paths that the future compiler would eventually build upon:

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`
- `test/testcase/asn.1/loader/`

## Related document

- `compiler-flow.md` — detailed compiler design sketch

When implementation begins, this document should be updated from the current design assumptions to the actual command-line, generated-source, and testcase behavior.
