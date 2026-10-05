# ASN.1 Parser → Semantic Construction → Runtime

> **Review baseline:** Revision 1097

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


## Revision 1097: grammar → semantic reconstruction

The important change is the explicit connection between stabilized grammar productions and semantic reconstruction. The parser is now being used to rebuild the ASN.1 semantic model while the implementation can switch production handling between LALR(1) and GLR where the grammar requires it.

```text
ASN.1 notation
      │
      ▼
production / rule
      │
      ├── LALR(1)
      └── GLR
            │
            ▼
    semantic reconstruction
            │
            ▼
       asn1_object
            │
            ▼
      asn1_runtime
```

This is a stronger milestone than simply saying that ASN.1 source files are parseable. It shows the grammar being used to reconstruct the semantic representation that the runtime already models. The distinction remains important: semantic reconstruction of the implemented production set is not the same as complete support for the ASN.1 language or a finished module loader.

## Loader: first integration step

Revision 1097 also gives the loader a small but meaningful step forward: the loader direction is beginning to connect the external ASN.1 source entry point with the parser/semantic-reconstruction path. It should still be described as an evolving integration point rather than a completed module loader.

The grammar resources also need to be distinguished:

```text
asn1notation.ptb → notation parsing / semantic construction
asn1.ptb         → broader loader grammar
```

A crucial documentation rule is:

> parseable does not mean implemented.

The current ASN.1 test inputs can be parsed as grammar, but that does not imply that every ASN.1 feature represented there has complete loader/runtime semantic support.

Revision 1097 is the boundary used here because the ASN.1 production/rule names are now stable enough to describe the actual semantic reconstruction path. This revision also demonstrates production-level switching between the LALR(1) and GLR parser paths while reconstructing ASN.1 notation into semantic objects.

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

**GPT Review**

Reviewed against the hotplace source/documentation state around **revision 1097**.


## 13. Revision 1097: Semantic Reconstruction Becomes Concrete

Revision 1097 changes the useful boundary of this review.

The parser is no longer best described only as:

```text
ASN.1 notation
    ↓
parse tree
    ↓
runtime
```

The implementation now has a concrete production vocabulary that can be
followed from grammar reduction into semantic reconstruction.

For notation-oriented input, the important path is:

```text
Statement
  ↓
Assignment
  ↓
TypeAssignment
  ↓
Type
  ↓
SimpleTypeSpec / TaggedTypeSpec /
ReferencedTypeSpec / constructed TypeSpec
  ↓
semantic reconstruction
  ↓
asn1_object / referenced type
  ↓
asn1_runtime
```

For constructed types, the grammar makes the semantic boundary explicit:

```text
SequenceTypeSpec / SetTypeSpec / ChoiceTypeSpec
        ↓
ComponentTypeLists
        ↓
ComponentTypeList
        ↓
ComponentType
        ↓
NamedType + Constraint / OptionalitySpec
        ↓
constructed ASN.1 runtime object
```

This is significant because the production names now describe actual semantic
units rather than being temporary parser implementation labels.

### LALR(1) and GLR have different semantic scopes

The two grammar paths should not be treated as merely duplicate parsers.

```text
LALR(1)
  └── ASN.1 notation-oriented grammar
       └── direct semantic reconstruction

GLR
  └── broader ASN.1 grammar
       ├── ModuleDefinition
       ├── EXPORTS / IMPORTS
       ├── parameterized assignments
       ├── ValueAssignment
       ├── ObjectClassAssignment
       └── InformationObjectAssignment
```

This explains why production/rule switching matters: the parser architecture
is being used to separate a relatively compact notation reconstruction path
from the broader module/loader grammar.

### Loader milestone

The loader should therefore be described as a new integration edge:

```text
ASN.1 source
    ↓
loader entry
    ↓
broader parser / GLR grammar
    ↓
semantic reconstruction
    ↓
runtime schema/type objects
```

Revision 1097 does not imply that every module-level ASN.1 feature is fully
implemented. It does establish a much clearer path for the loader to move from
a skeleton toward actual source-to-runtime reconstruction.

The distinction remains:

```text
grammar coverage
      ≠
semantic implementation
      ≠
complete loader support
```
