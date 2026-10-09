# Hotplace Parser Evolution

> **Review baseline:** Revision 1102

## Review thesis

**The parser's architectural evolution is a progression from parser mechanics toward explicit generated resources and semantic production vocabulary, with GLR becoming the mechanism for handling broader grammar structure rather than simply replacing LALR.**

## Evolution path

```text
lexer / CFG / LALR(1)
        ↓
context-dependent parser experiments
        ↓
Aho-Corasick related switching/reduction ideas
        ↓
GLR
        ↓
large parsing/action tables
        ↓
external binary parsing tables
        ↓
.ptb resources
```

The important story is not simply that the parser changed algorithms. Each stage exposed a new pressure on the surrounding architecture: context-sensitive switching complicated parser control, GLR expanded the grammar strategy, table size made generated data expensive to keep inside the source representation, and the resulting `.ptb` resources became explicit build inputs.

## From parser experiments to GLR

Early work explored lexer/CFG/LALR(1) parsing and context-aware switching ideas. The Aho-Corasick reducer experiments belong to that stage: they investigated how parsing decisions could be reduced or redirected according to context.

The eventual move to GLR changed the architecture more substantially. GLR allowed the broader ASN.1 grammar to be represented without forcing every ambiguity or structural choice into a single deterministic LALR path.

For ASN.1, the distinction between parser paths remains concrete at revision 1102:

```text
LALR(1)
  └── notation-oriented grammar
       └── semantic reconstruction

GLR
  └── broader grammar
       ├── ModuleDefinition
       ├── EXPORTS / IMPORTS
       ├── parameterized assignments
       ├── ValueAssignment
       ├── ObjectClassAssignment
       └── InformationObjectAssignment
```

The architectural point is therefore not “GLR replaced LALR.” The two paths have different semantic scopes and can participate in the same ASN.1 processing strategy.

## Generated parsing tables become resources

As the parsing/action table grew, generated parser state stopped being a convenient detail of source code and became a resource that needed an explicit lifecycle.

```text
test/tool/makeparsingtable
          ↓
binary_parsing_table::learn()
          ↓
        .ptb
          ↓
etc/parsingtable/parsingtable.zip
          ↓
CMake configure / generate
          ↓
build / test resources
```

This separation has a practical consequence: parser behavior depends on both the grammar/generation source and the generated table resource. The build system therefore becomes part of parser reproducibility rather than merely a wrapper around compilation.

## Production vocabulary becomes semantic vocabulary

The revisions through 1102 preserve the stable production/rule vocabulary while extending the parameterized grammar and module-level semantics.

The notation-oriented hierarchy includes:

```text
Statement
  └── Assignment
        └── TypeAssignment
              ├── DefinedType
              ├── Type
              │    ├── SimpleTypeSpec
              │    ├── TaggedTypeSpec
              │    ├── ReferencedTypeSpec
              │    ├── EnumeratedType
              │    ├── SequenceTypeSpec
              │    ├── SequenceOfTypeSpec
              │    ├── SetTypeSpec
              │    ├── SetOfTypeSpec
              │    └── ChoiceTypeSpec
              └── Constraint
```

Constructed types continue through `ComponentTypeLists`, `ComponentTypeList`, `ComponentType`, and `NamedType`, while constraints proceed through `ConstraintSpec`, `SubtypeElementSetSpec`, `SubtypeElement`, and `PrimaryElement`.

These names matter architecturally because they are the vocabulary used to connect grammar reduction with semantic reconstruction. They are no longer merely parser-internal labels.

## Parameterized grammar and lexer changes through revision 1102

The parameterized ASN.1 path is still an area of active grammar work. Revision 1102 changes the CFG productions for `ParameterizedAssignment`, `ParameterizedType`, and `ParameterizedValue`. It also adds dedicated lexical handlers for single-quoted strings and hexadecimal strings, while removing `handle_asn1parameterized` because the current parameterized-value handling has known limits.

The practical distinction is important: a grammar production or lexer handler records how input is recognized, but does not by itself establish full semantic construction or complete support for parameterized ASN.1. The same review discipline applies at each layer: grammar coverage, parse-tree shape, semantic reconstruction, module linkage, and loader behavior need separate evidence.

The binary parsing-table format also advanced from revision 1 to revision 2. The generated `.ptb` files and the table reader/writer therefore need to be treated as a versioned resource pair; an updated grammar source alone is not the whole parser update.

## Resource roles

For ASN.1, the generated resources have different purposes:

```text
asn1notation.ptb → notation parsing / semantic construction (table revision 2)
asn1.ptb         → broader loader grammar (table revision 2)
```

Keeping these roles distinct prevents a large parsing table from being treated as proof of complete ASN.1 language support.

## Why the evolution matters

The parser evolution can be summarized as a chain of architectural consequences:

```text
more expressive grammar
        ↓
more complex parser state
        ↓
larger generated tables
        ↓
externalized parser resources
        ↓
explicit build integration
        ↓
stable production vocabulary
        ↓
semantic reconstruction
```

This is why the parser history matters to the rest of hotplace: the parser did not evolve in isolation. Its changes affected resource generation, build integration, ASN.1 semantic construction, and eventually the loader path.

## Strengths

- The parser architecture evolved in response to concrete grammar and table-size pressures.
- Generated parser data has an explicit resource lifecycle.
- LALR(1) and GLR can serve different grammar scopes.
- Stable production names provide a bridge from grammar structure to semantic reconstruction.

## Costs and limitations

The resulting system has more moving parts than a parser whose tables are generated and discarded during compilation. Grammar changes, table generation, packaged resources, and build configuration must remain synchronized. The coexistence of LALR(1) and GLR also means that parser selection is part of the architecture rather than a transparent implementation detail.

## Current state

Revision 1102 adds another layer to that architecture: the ASN.1 parameterized-assignment/type/value grammar has changed, lexer handling has been adjusted, and the binary parsing-table format is now at revision 2. LALR(1)/GLR still serve different grammar scopes, and external `.ptb` resources remain part of parser generation and build integration.

### Related source / documents

- `sdk/io/parser/`
- `test/tool/makeparsingtable`
- `etc/parsingtable/`
- `sdk/io/asn.1/`
- `sdk/io/parser/parser-generation.md`
- `sdk/io/parser/parsing-table-binary-format.md`

---

**GPT Review**

Reviewed against the hotplace source/documentation state around **revision 1102**.
