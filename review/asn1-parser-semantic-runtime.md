# ASN.1 Parser → Semantic Construction → Runtime

> **Review baseline:** Revision 1097

## Review thesis

**The important ASN.1 parser milestone is not broader grammar coverage by itself, but the point where production rules became a stable vocabulary for reconstructing semantic runtime objects and opening a concrete path toward the loader.**

## Architectural view

```text
ASN.1 notation
      ↓
lexing / parsing
      ↓
production / rule
      ↓
LALR(1) / GLR
      ↓
semantic reconstruction
      ↓
asn1_object / referenced type
      ↓
asn1_runtime schema/type lookup
      ↓
runtime ASN.1 object
```

This makes the parser more than a syntax recognizer. The grammar now provides the structure from which the semantic ASN.1 model can be reconstructed, while the runtime provides the destination in which that model can be represented and used.

## From grammar vocabulary to semantic objects

The revision 1097 notation path can be followed through a concrete production hierarchy:

```text
Statement
  ↓
Assignment
  ↓
TypeAssignment
  ↓
Type
  ├── SimpleTypeSpec
  ├── TaggedTypeSpec
  ├── ReferencedTypeSpec
  ├── EnumeratedType
  ├── SequenceTypeSpec
  ├── SequenceOfTypeSpec
  ├── SetTypeSpec
  ├── SetOfTypeSpec
  └── ChoiceTypeSpec
        ↓
semantic reconstruction
        ↓
asn1_object / referenced type
```

For constructed types, the component vocabulary carries the structure needed by semantic construction:

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

The significance of these names is not that the grammar has become easier to read. The significance is that the same structural units can now be followed from parsing into semantic reconstruction. The production vocabulary therefore becomes an architectural seam between syntax and meaning.

## The runtime side

The `testcase_basic2.cpp` path provides a compact example of the semantic destination:

```text
Person ::= SEQUENCE {
    name VisibleString,
    age INTEGER DEFAULT 20
}
        ↓
semantic ASN.1 objects
        ↓
asn1_runtime
```

Within that construction model, `define()` establishes a referenced type together with its object, while `refer()` represents a reference by name. `asn1_runtime::add_schema()` provides the separate schema registration step.

This distinction matters because parsing does not directly create an undifferentiated “runtime object.” The semantic layer first establishes definitions, references, constructed objects, and their relationships; the runtime then provides lookup and schema-level use.

## LALR(1) and GLR are different parts of the architecture

The two parser paths should not be described simply as two interchangeable implementations of the same grammar.

```text
LALR(1)
  └── ASN.1 notation-oriented grammar
       └── semantic reconstruction

GLR
  └── broader ASN.1 grammar
       ├── ModuleDefinition
       ├── EXPORTS / IMPORTS
       ├── parameterized assignments
       ├── ValueAssignment
       ├── ObjectClassAssignment
       └── InformationObjectAssignment
```

The GLR grammar provides the broader language structure needed for the loader direction, while the LALR(1) grammar provides the more focused notation-oriented reconstruction path. Revision 1097's production-level switching is therefore significant because it lets parser selection participate in the semantic reconstruction strategy rather than treating parser choice as an isolated implementation detail.

## Constraint semantics fit below the parser

The constraint path reinforces the same boundary:

```text
ASN.1 grammar
    ↓
Constraint / ConstraintSpec / SubtypeElement...
    ↓
asn1_constraint_evaluator
    ↓
set / range semantics
```

The parser identifies the structure of a constraint. Semantic evaluation gives that structure a value-domain meaning. The reusable set model can then operate without knowing that its input originated in ASN.1.

This is an important complement to the parser/runtime relationship: **the parser is responsible for structure, while semantic layers translate that structure into domain objects and operations.**

## Loader: the new integration edge

The loader is where the broader parser and semantic model begin to meet an external ASN.1 source entry point:

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

Revision 1097 should be described as the beginning of this integration, not as a completed module loader. The loader has moved beyond a purely isolated skeleton, but module-level ASN.1 support still has a distinction between grammar coverage, semantic implementation, and complete loading behavior.

The parsing resources also have different roles:

```text
asn1notation.ptb → notation parsing / semantic construction
asn1.ptb         → broader loader grammar
```

That distinction prevents the existence of a parse table from being mistaken for complete language support.

## Why this architecture matters

The architectural value of the 1097 change is the creation of a continuous path:

```text
syntax
  ↓
production vocabulary
  ↓
semantic reconstruction
  ↓
runtime representation
  ↓
loader integration
```

Previously, these concerns could be understood as separate parser, semantic, runtime, and loader pieces. The production vocabulary now provides a concrete way to reason about how they connect. That makes further ASN.1 implementation work incremental: new grammar coverage can be evaluated not only by whether it parses, but by whether it has a semantic reconstruction path and a runtime destination.

## Strengths

- Parser productions have become useful semantic vocabulary rather than remaining opaque parsing machinery.
- LALR(1) and GLR can serve different stages of the ASN.1 processing path.
- Semantic construction provides an explicit boundary between syntax and runtime representation.
- The runtime model already has distinct notions of definition, reference, and schema registration that the parser can reconstruct toward.
- The loader now has a concrete direction from source input through parsing and semantic reconstruction.

## Costs and limitations

The architecture introduces several layers that must remain synchronized: grammar productions, semantic reconstruction actions, runtime object relationships, and loader behavior. A grammar production can therefore exist without having complete semantic support, and semantic construction can exist without implying complete module loading.

The distinction is important enough to state explicitly:

```text
grammar coverage
      ≠
semantic implementation
      ≠
complete loader support
```

Revision 1097 establishes the connection between these layers; it does not claim that every ASN.1 language feature has crossed all of them.

## Current state

Revision 1097 is a meaningful architectural boundary for ASN.1 because the production/rule vocabulary is stable enough to describe the semantic reconstruction path, LALR(1)/GLR production switching is part of that path, and the loader has begun moving toward source-to-runtime integration.

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
