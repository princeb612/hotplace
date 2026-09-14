# ASN.1 Semantic Construction — Notation to Runtime Object

**Edition 1 · Revision 1083**

## Context

The ASN.1 work has reached a useful boundary: ASN.1 notation can be parsed and reconstructed into the existing runtime `asn1_object*` model, including constraints.

This document owns the question:

> How does textual ASN.1 become a semantic runtime schema?

It connects the parser, parse tree, semantic construction, runtime ASN.1 types, and constraint model. Encoding/decoding behavior remains owned by the corresponding ASN.1 runtime topics and tests.

## History

The CHANGELOG gives the following development path:

- **Revision 1031** — ASN.1 runtime, builtin type, referenced type
- **Revision 1044** — ASN.1 constraints
- **Revision 1056–1058** — strongly-typed decoding
- **Revision 1064** — CFG grammar and LALR parser
- **Revision 1069** — parse tree
- **Revision 1070** — parse tree visitor
- **Revision 1072** — ASN.1 parser usertype applied
- **Revision 1074** — `asn1_publisher` first step
- **Revision 1077** — Named Number List, Named Bit List, ENUMERATED
- **Revision 1078** — CHOICE, DEFAULT, OPTIONAL
- **Revision 1081–1082** — constraints in `asn1_publisher`, including exclusive boundaries and string ranges
- **Revision 1083** — `string_set` `erase_range`, `intersect`

The history shows the transition from an ASN.1 runtime model, through parser infrastructure, toward semantic reconstruction of that model from notation.

## Conceptual

Parsing and construction are different concerns.

```text
ASN.1 notation
      │
      ▼
 lexical analysis
      │
      ▼
    tokens
      │
      ▼
  LALR parsing
      │
      ▼
  parse tree
      │
      ▼
semantic construction
      │
      ▼
  asn1_object*
```

The parse tree represents the syntactic result. Semantic construction interprets grammar productions and combines their semantic values into objects that have meaning in the ASN.1 runtime model.

The important boundary is therefore:

```text
syntax
  → parse structure
  → semantic value
  → runtime object
```

A grammar symbol does not necessarily become an `asn1_object*`. Some symbols carry textual values, some carry ASN.1 options, and constraint productions carry typed constraint objects. The semantic stack is the temporary state that allows these different values to participate in the same reduce process.

### Semantic node

`asn1_semantic_node` combines the information needed during reconstruction:

```text
asn1_semantic_node
 ├── symbol / value          parse-tree information
 ├── object                  asn1_object*
 ├── option                  ASN.1 field/type option
 └── constraint state
      ├── variant values
      ├── category
      └── typed constraint pointer
```

The node is therefore not simply a parse-tree node. It is a temporary semantic value whose contents depend on the grammar production currently being reduced.

### Reduction is semantic construction

For a reduction:

```text
A → B C D
```

the publisher consumes the semantic values produced for `B`, `C`, and `D`, interprets the production, and pushes one semantic value for `A`.

Conceptually:

```text
shift:
    token / node
       ↓
    semantic stack

reduce:
    RHS semantic values
       ↓
    production handler
       ↓
    semantic value
       ↓
    semantic stack
```

This makes the LALR reduction sequence useful beyond syntax recognition: it supplies the order in which semantic components are assembled.

### Runtime object is the result

The final result is an `asn1_object*`, not a parse tree.

The existing runtime hierarchy supplies the semantic representation for builtin and constructed types, referenced types, tagging, and constraints. `asn1_builder` is the public construction entry point; its parse-tree overload delegates to `asn1_publisher`.

## Structural

### Publisher and semantic stack

The central relationship is:

```text
parse_tree
    │
    ▼
parse_tree_visitor
    │
    ├── shift ──→ push asn1_semantic_node
    │
    └── reduce ─→ handler(node, context)
                         │
                         ▼
                  pop RHS semantic values
                         │
                         ▼
                  construct semantic value
                         │
                         ▼
                     push result
```

`asn1_publisher` owns the handler map and the construction process. `asn1_publisher_context` owns the temporary semantic stack.

`asn1_semantic_node` uses reference-counted ownership for the runtime object and constraint pointer, allowing semantic values to be copied while retaining the underlying object.

### Production handlers

Handlers are registered by grammar symbol. The current implementation separates ordinary ASN.1 construction from constraint construction.

Representative semantic productions include:

```text
StatementSequence
StatementSequenceOf
StatementSet
StatementSetOf
StatementChoice
FieldList
Field
FieldOpt

TypeSpec
TypeBase
ReferencedType
TaggedType
TagPrefix
EnumType
EnumList
EnumItem
SimpleType
```

Constraint productions are handled separately:

```text
Constraint
ConstraintExpr
SubtypeElementSet
SubtypeElement
PrimaryElement
ValueElement
```

The distinction matters because a constraint reduction does not immediately have to become the final ASN.1 type. It first produces a typed constraint semantic value that can later be attached to the relevant ASN.1 object.

### Constraints

The constraint path has its own semantic composition.

```text
Constraint
    ↓
ConstraintExpr
    ↓
SubtypeElementSet
    ↓
SubtypeElement
    ↓
PrimaryElement
    ↓
ValueElement
```

Combinations such as union, intersection, and EXCEPT are converted into typed constraint objects. Range boundaries are represented with their inclusive/exclusive semantics, while string ranges use the corresponding string constraint representation.

At Revision 1083, `string_set::erase_range` and `intersect` are part of this constraint-supporting structure.

The important conceptual point is that constraints are not retained merely as source text. They become semantic objects that belong to the runtime ASN.1 model.

### Builder boundary

The public path is:

```text
asn1_parser
    │
    ▼
parse_tree
    │
    ▼
asn1_builder::build(parse_tree, object)
    │
    ▼
asn1_publisher::build
    │
    ▼
asn1_object*
```

`asn1_builder` also provides direct object-building helpers for ASN.1 entities and tags. The parse-tree overload is specifically the bridge from notation-derived syntax to runtime semantic construction.

## Flow

A complete reconstruction flow can be viewed as two passes over different representations:

```text
                 PASS 1
        notation → parse structure
                 │
                 ▼
        lexical analyzer
                 │
                 ▼
             LALR parser
                 │
                 ▼
             parse_tree

                 PASS 2
        parse structure → meaning
                 │
                 ▼
        parse_tree_visitor
                 │
          shift / reduce
                 │
                 ▼
        asn1_publisher_context
                 │
                 ▼
        production handlers
                 │
                 ├── type/object
                 ├── option
                 └── constraint
                 │
                 ▼
             asn1_object*
```

The second pass does not need to rediscover the grammar. It reuses the parser's recorded shift/reduce structure and attaches semantic actions to reductions.

For a constructed type, the process is therefore conceptually:

```text
child type semantics
       +
field name / option
       +
constructed-type production
       ↓
constructed ASN.1 object
```

For a constrained type:

```text
constraint syntax
       ↓
constraint semantic object
       ↓
type/field construction
       ↓
runtime ASN.1 object with constraint
```

## Study & Verification

The ASN.1 parser test path provides a direct reconstruction experiment.

The test parses notation into a `parse_tree`, traces the tree using `parse_tree_visitor`, and then calls:

```text
asn1_builder::build(&pt, &obj)
```

The resulting object is published back to notation and compared with the input notation when an expected normalized form is not supplied.

The current parser test exercises publisher coverage for:

```text
StatementSequence / SequenceOf
StatementSet / SetOf
StatementChoice
Field / FieldOpt
TypeSpec / TypeBase
ReferencedType
TaggedType / TagPrefix
EnumType / EnumList / EnumItem
SimpleType
```

Constraint work is exercised separately through the ASN.1 constraint test area and the parser reconstruction path.

This gives a useful verification loop:

```text
notation
   ↓
parse
   ↓
parse_tree
   ↓
semantic construction
   ↓
asn1_object*
   ↓
publish notation
   ↓
compare
```

The loop verifies structural reconstruction rather than only parser acceptance.

## Status

At Revision 1083:

- ASN.1 notation parsing has CFG/LALR infrastructure and a parse-tree representation.
- Parse-tree visitation exposes the shift/reduce sequence used for reconstruction.
- `asn1_publisher` converts semantic grammar reductions into runtime ASN.1 objects.
- Constructed types, referenced types, tagging, ENUMERATED/named lists, CHOICE, DEFAULT, and OPTIONAL are covered by the publisher path.
- Constraints have been integrated into the same semantic-construction path, including range/string-range handling and compound constraint operations.
- The resulting runtime representation is an existing `asn1_object*` model rather than a separate notation-only representation.
- Revision 1083 marks the current constraint-supporting `string_set` operations as part of this completed reconstruction stage.

The next natural question is no longer how to create a runtime object from notation, but how that runtime schema participates in the broader runtime workflow: type lookup, value construction, encoding/decoding, and possible C++ source generation.
