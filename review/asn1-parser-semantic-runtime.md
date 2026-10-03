# ASN.1 Parser → Semantic Construction → Runtime

> **Review baseline:** Revision 1096

This review connects ASN.1 grammar processing to semantic construction and runtime objects.

```text
ASN.1 notation
      ↓
lexing / parsing
      ↓
LALR parsing table
      ↓
semantic construction
      ↓
asn1_object
      ↓
asn1_runtime schema/type lookup
      ↓
runtime ASN.1 object
      ↓
encode / decode / strongly typed use
```

The `testcase_basic2.cpp` path is the important example: ASN.1 notation is turned into runtime type objects, with `define()` representing a definition and `refer()` representing a reference.

The grammar resources also need to be distinguished:

```text
asn1notation.ptb → notation parsing / semantic construction
asn1.ptb         → broader loader grammar
```

A crucial documentation rule is:

> parseable does not mean implemented.

The current ASN.1 test inputs can be parsed as grammar, but that does not imply that every ASN.1 feature represented there has complete loader/runtime semantic support.

Revision 1096 is used as the boundary because production/rule names were expected to be close to stabilization there.

### Related source / documents

- `sdk/io/asn.1/`
- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/testcase_construct.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `asn1notation.ptb`
- `asn1.ptb`
- ASN.1 loader/compiler/runtime documentation

---

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1096                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
