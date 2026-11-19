# Parser — Grammar to Parse Structure

**Edition 1 · Revision 1132**

> Source base : Revision 1132

## Context

The parser work grew from a notation-oriented path into a broader grammar model. LALR and GLR provide distinct execution mechanisms; the reader-facing boundary is simpler: turn language structure into a parse result that later stages can interpret.

This document owns the parser question:

> How does a grammar become an executable parser, and how does the parser expose enough structure for semantic construction?

The ASN.1 parser supports selectable LALR(1) and GLR paths. In the current source, `asn1_module::add_schema()` selects GLR, while advisor-provided parser instances retain the distinct build/import and notation/general-parser roles. Do not describe GLR as merely an unused experiment or claim every parser entry point uses the same path.

## History

The CHANGELOG gives the following parser-oriented sequence:

- **Parse-tree and notation foundation**
  - **Revision 1064** — LALR parser and CFG for ASN.1 notation
  - **Revision 1069** — parse tree
  - **Revision 1070** — parse-tree visitor
  - **Revision 1072** — ASN.1 parser usertype applied
- **Grammar and parser-engine expansion**
  - **Revision 1087** — `lalr1_parser` import
  - **Revision 1088** — CFG for ASN.1 module
  - **Revision 1089** — context-aware parser switching pattern
  - **Revision 1090** — GLR parser and integrated CFG work covering ASN.1 notation, module, parameterized constructs, and information object class
  - **Revision 1091** — CFG for ASN.1 information object class
  - **Revision 1093** — CFG for ASN.1 extension marker versions 1 and 2.
  - **Revision 1094** — parser-table binary layout and external table import.
  - **Revision 1095** — build infrastructure changes supporting the parser-table workflow.
  - **Revision 1096** — graph-structured stack (GSS) support for GLR and parse-tree construction fixes.
- **Loader and module integration**
  - **Revision 1097** — loader begins parsing file/memory input to a `parse_tree` (first step).
  - **Revision 1099** — `IMPORTS`, `EXPORTS`, module linkage, `resolve()` and `is_resolvable()` are exercised in the module path.
  - **Revision 1100** — shared ASN.1 knowledge and parser/publisher providers move under `asn1_advisor` (renamed from `asn1_resource`).
  - **Revision 1102** — `asn1_runtime`/`asn1_runtime_context` are renamed to `asn1_module`/`asn1_module_context`; parameterized assignment/type/value grammar is extended and parser tables move to revision 2.
  - **Revision 1103** — `asn1_publisher` fixes `TypeAssignment` semantic publication.
  - **Revision 1104** — parameterized type/value semantic prototypes; module registry renamed to `asn1_modules`; binary parsing-table format revision 3.
  - **Revisions 1120/1122** — runtime parameterized-type specialization and instantiation work.
  - **Revision 1123** — publisher reconstruction of parameterized type definitions and formal parameter lists.
  - **Revision 1124** — parse-tree visitor state scopes parameterized-instantiation context to descendants; publisher handlers collect actual type/value parameters and specialize the referenced type. The ASN.1 parsing-table format advances to revision 4.
  - **Revision 1125** — move-aware specialization overloads support transferring collected parameter values into specialized objects.

The important direction is parser selection at a stable semantic boundary, not a simple LALR-to-GLR replacement story:

- **GLR infrastructure**
  - The GSS and parse-tree fixes from Revision 1096 support the GLR path.
- **Module integration**
  - The module/schema path selects GLR through `asn1_module::add_schema()`; advisor-provided notation parsers retain LALR build/import paths, while GLR build/import paths are also exercised.
- **Parameterized semantic boundary**
  - Parameterized support has advanced beyond the Revision 1104 prototypes. The active parser → loader → publisher path reconstructs a concrete `FRAME` instantiation, while direct semantic tests exercise additional specializations. This is bounded integration, not proof that every parameter form or nested construct is complete.

The two parser mechanisms and their provider/configuration paths should remain explicit in the explanation.

## Why the parser has become a separate study topic

The parser became a distinct topic because ASN.1 work reached a point where recognizing notation and understanding its meaning could no longer be treated as one operation. The project first needed a reusable grammar/parser boundary, then a parse-tree boundary, and only after that a semantic-construction boundary.

That gives the reader the important direction of the work:

```text
text
 ↓
recognize grammar
 ↓
retain structure
 ↓
interpret meaning
```

LALR and GLR are mechanisms inside the first step. Both remain relevant to the current parser paths, but the reason for the parser work is the boundary it creates for semantic construction.

## Conceptual

The parser has several distinct responsibilities:

```text
grammar
   ↓
CFG representation
   ↓
parser mechanism
   ├── LALR  → deterministic action selection
   └── GLR   → multiple valid action paths when needed
   ↓
parse result
   ↓
semantic construction
```

The distinction between parser mechanism and semantic construction is important. LALR and GLR determine how grammar alternatives are explored; `asn1_publisher` determines what those reductions mean in the ASN.1 runtime model.

### LALR path

The LALR path remains available for notation-focused parsing:

```text
ASN.1 notation
      ↓
 lexical analyzer
      ↓
   CFG tables
      ↓
  lalr1_parser
      ↓
  parse_tree
      ↓
 asn1_publisher
      ↓
 asn1_object*
```

The integrated module/schema path is different: `asn1_module::add_schema()` creates an `asn1_parser` configured for GLR and passes the resulting parse tree through the shared `asn1_publisher`. Parser instances are supplied through `asn1_advisor`; LALR(1) and GLR remain distinct selectable paths rather than one universal parser object.

### GLR path

The GLR path is used by the integrated module/schema flow, where broader grammar coverage requires it:

```text
broader ASN.1 CFG
      ↓
   glr_parser
      ↓
 multiple parse paths
      ↓
 parse result / ambiguity handling
      ↓
 semantic construction
```

This does not mean every parser entry point uses GLR. The notation-oriented provider paths still expose LALR, while the integrated module/schema path selects GLR. Parameterized semantic instantiation is now integrated for a bounded path: Revision 1124 adds visitor-state propagation and actual-argument collection, and the active `test_parameterized2()` and `test_parameterized3()` cases check selected inline `FRAME` and file-based `example6.asn1` reconstructions. The broader grammar and semantic edge cases remain separate coverage questions.

The GLR path makes the broader grammar executable where a deterministic LALR table would otherwise require grammar-specific conflict avoidance or restructuring.

### Graph-structured stack

Revision 1096 introduces a graph-structured stack (GSS) for the GLR path. Instead of treating every parser branch as an independent linear stack, the GSS allows stack paths to share nodes while preserving multiple parent paths. This provides the structure needed for GLR reductions and path reconstruction. The integrated module/schema path selects GLR; LALR remains available as a separate parser path.

Conceptually:

```text
GLR parser
    ↓
GSS node graph
    ├── shared stack nodes
    ├── multiple parent paths
    └── path reconstruction
             ↓
        parse structure
```

Revision 1096 corrected GLR parse-tree construction. Subsequent module work uses the GLR-selected path for schema parsing and semantic publication; the module is now named `asn1_module`, and it records imports/exports and supports reference-resolution checks.

A GLR parse does not by itself create an ASN.1 runtime object. The resulting semantic alternatives still need a construction policy.

## Structural

### CFG as the common grammar description

The parser layer provides `cfg_grammar` as the grammar representation used to describe productions and terminals. The ASN.1 work is extending that description from notation toward larger language units such as modules and parameterized constructs.

Conceptually:

```text
ASN.1 language
 ├── notation
 ├── module
 ├── parameterized construct
 └── information object class
              │
              ▼
          one CFG model
              │
       ┌──────┴──────┐
       ▼             ▼
     LALR           GLR
   notation       module /
   provider       schema path
```

At Revision 1132, the unified CFG and its parser providers feed a module path that selects GLR for `add_schema()`. Grammar coverage and semantic coverage are not identical: the active publisher path collects actual type/value parameters and specializes a referenced parameterized type, and the parameterized testcase checks a concrete reconstruction. This does not establish complete parameter binding/substitution for every grammar form.

### Parser result and semantic construction

The parse tree is a boundary between syntax processing and meaning construction.

```text
parser
  ↓
parse structure
  ↓
asn1_publisher
  ↓
semantic value
  ↓
asn1_object*
```

This preserves the existing design direction from the ASN.1 semantic-construction study: parser reductions expose structure; publisher handlers interpret that structure.

Publisher coverage must track grammar coverage, but recognition and semantic instantiation are distinct. Module and TypeAssignment publication are exercised. Parameterized definitions and instantiations now have publisher handlers; the active `test_parameterized2()` path checks a parsed `FRAME` definition and `MyPacket ::= FRAME{ OCTET STRING, 1024 }` reconstruction, while `test_parameterized3()` checks a parameterized module. These tests establish selected integration paths, not complete parameter binding, substitution, or instantiated-object behavior across all ASN.1 forms.

### Context-aware parser switching

Revision 1089 introduced a context-aware parser switching pattern. The relevant idea is that parser behavior can be selected from grammar/context information rather than hard-coding one parser mechanism for every language fragment.

This remains useful because the parser providers preserve a notation-oriented LALR path while the integrated module/schema path uses GLR. The two paths can coexist without treating one as a universal replacement for the other.

## Flow

The notation and module/schema paths should be kept visually separate; both parser engines are present in active source paths:

```text
                    ASN.1 notation
                          │
                          ▼
                    lexical analysis
                          │
                          ▼
                  integrated CFG model
                     │           │
             notation path       module/schema path
                     ▼           ▼
                   LALR         GLR
                     │           │
                     └─────┬─────┘
                           ▼
                      parse result
                           │
                           ▼
                   semantic construction
                           │
                    asn1_publisher
                           │
                           ▼
                      runtime model
```

The notation-oriented provider path:

```text
asn1_advisor notation parser provider
        ↓
LALR(1) table build or import
        ↓
parse_tree
        ↓
syntax result
```

The integrated module/schema path:

```text
asn1_module::add_schema()
        ↓
asn1_parser(parser_type_t::glr, true)
        ↓
glr_parser
        ↓
parse_tree
        ↓
asn1_publisher
        ↓
asn1_object* / module schema
```

The parameterized loader/publisher integration path:

```text
asn1_loader::load()
        ↓
parse_tree
        ↓
asn1_publisher::build()
        ↓
collect actual type/value parameters
        ↓
specialize parameterized type
        ↓
module representation comparison
```

The loader path has advanced since Revision 1097: input can flow through parser and publisher into module-level information, including IMPORTS/EXPORTS and resolvability checks. The parameterized path is now exercised for selected definitions and instantiations; complete support for all parameter forms remains a separate coverage question.

## Study & Verification

The parser study should verify the layers independently before combining them:

1. **CFG coverage** — track the selected notation, module, parameterized-construct, information-object-class, and extension-marker productions represented by the unified CFG.
2. **LALR notation path** — preserve and verify the notation-oriented build/import parser providers.
3. **GLR module/schema path** — verify the GLR path selected by `asn1_module::add_schema()` and the parser's broader grammar cases.
4. **Semantic construction** — keep syntax acceptance distinct from semantic publication and runtime-object validation.
5. **Parameterized integration** — retain the bounded parser → loader → publisher checks for concrete type/value actual arguments, without generalizing them to every ASN.1 parameter form.
6. **Loader/module integration** — track file/memory loading, module construction, IMPORTS/EXPORTS, and reference resolution as separate assertions.

The verification target is therefore not simply “GLR parses ASN.1.” It is the complete boundary:

```text
CFG
 ↓
parser result
 ↓
semantic interpretation
 ↓
runtime schema/object
```

## Status

At Revision 1105:

- `asn1_module::add_schema()` currently selects GLR through `asn1_parser`; LALR(1) remains available through the parser-provider architecture.
- The parser layer contains both LALR and GLR implementations.
- The integrated CFG now covers ASN.1 notation, module, parameterized constructs, information object class, and extension marker versions 1 and 2.
- GLR uses the GSS-based parsing path and corrected parse-tree construction, and is used by the current module `add_schema()` flow.
- Context-aware parser switching has been explored as a way to keep parser selection dependent on grammar/context.
- `asn1_module` stores module definitions, imports/exports, values, and reference/linkage state; `resolve()` and `is_resolvable()` support dependency checks.
- `asn1_publisher` remains the semantic-construction boundary. Broader grammar coverage is expected to require additional handlers.
- Revisions 1102–1103 add parameterized grammar productions and fix `TypeAssignment` semantic publication; full parameterized instantiation remains future work.

## Related topics

- [ASN.1 Semantic Construction](../../asn.1/README.md)
- `sdk/io/parser/cfg_grammar.*`
- `sdk/io/parser/lalr1_parser.*`
- `sdk/io/parser/glr_parser.*`
- `sdk/io/parser/parse_tree.*`
- `sdk/io/asn.1/runtime/asn1_module.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/loader/asn1_loader.*`
