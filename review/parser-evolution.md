# Hotplace Parser Evolution

> **Review baseline:** Revision 1097

Hotplace's parser is best understood as an evolution.

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

The move toward GLR and the growth of the action table eventually made generated parser data a build concern. External `.ptb` resources separate that generated data from the source/build itself.

```text
test/tool/makeparsingtable
          ↓
binary_parsing_table::learn()
          ↓
        .ptb
          ↓
etc/parsingtable/parsingtable.zip
          ↓
CMake configure/generate
```

For ASN.1, `asn1notation.ptb` and `asn1.ptb` have different purposes and should not be treated as interchangeable.

Revision 1097 is the concrete boundary for production/rule naming. Earlier parser experiments remain historical stages, but the grammar can now be discussed using the stabilized ASN.1 production/rule vocabulary rather than only describing the parser in generic LALR/GLR terms.

### Related source / documents

- `sdk/io/parser/`
- `test/tool/makeparsingtable`
- `etc/parsingtable/`
- `sdk/io/asn.1/`
- `sdk/io/parser/parser-generation.md`
- `sdk/io/parser/parsing-table-binary-format.md`

---

**GPT Review**

Reviewed against the hotplace source/documentation state around **revision 1097**.


## 12. Production / Rule Vocabulary at Revision 1097

Revision 1097 is a useful point to stop describing the ASN.1 grammar only in
terms of "LALR versus GLR" and start naming the actual grammar structure.

The LALR(1) notation grammar has a compact notation-oriented hierarchy:

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

Constructed components are represented explicitly through:

```text
ComponentTypeList
  └── ComponentType
        └── NamedType
              └── Type

ComponentType
  ├── NamedType
  ├── NamedType + Constraint
  ├── NamedType + OptionalitySpec
  └── NamedType + Constraint + OptionalitySpec
```

Constraint grammar is also now concrete enough to use directly in the review:

```text
Constraint
  └── ConstraintSpec
        ├── SubtypeElementSetSpec
        │     └── SubtypeElement
        │           └── PrimaryElement
        └── ALL EXCEPT SubtypeElementSetSpec

PrimaryElement
  ├── ValueElement
  ├── range forms
  ├── SIZE Constraint
  ├── FROM Constraint
  ├── PATTERN string
  └── nested ConstraintSpec
```

The GLR grammar extends this vocabulary to module-level ASN.1:

```text
Start
  └── ModuleStatementList
        └── ModuleStatement
              └── ModuleDefinition
                    ├── ModuleIdentifier
                    ├── TagDefault
                    ├── ExtensionDefault
                    └── ModuleBody
                          ├── Exports
                          ├── Imports
                          └── AssignmentList
```

Within assignments, revision 1097 exposes the intended semantic domains more
clearly:

```text
Assignment
  ├── TypeAssignment
  ├── ValueAssignment
  ├── ObjectClassAssignment
  └── InformationObjectAssignment
```

Parameterized type assignment and parameter lists are represented by
`ParameterList` / `Parameter`, while object-class-related grammar is present
as part of the broader GLR grammar.

The important architectural point is not that every production above is
already fully implemented semantically. Rather, the grammar vocabulary is now
stable enough that parser behavior, semantic reconstruction, and loader work
can be discussed using the actual names from the implementation.
