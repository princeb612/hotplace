# Parser — Grammar to Parse Structure

**Edition 1 · Revision 1103**

## Context

The parser work is currently extending a working notation-oriented path toward a broader grammar model. LALR and GLR are mechanisms used to explore that problem; the reader-facing boundary is simpler: turn language structure into a parse result that later stages can interpret.

This document owns the parser question:

> How does a grammar become an executable parser, and how does the parser expose enough structure for semantic construction?

The ASN.1 parser supports selectable LALR(1) and GLR paths. In the current source, `asn1_module::add_schema()` selects GLR, while advisor-provided parser instances retain the distinct build/import and notation/general-parser roles. Do not describe GLR as merely an unused experiment or claim every parser entry point uses the same path.

## History

The CHANGELOG gives the following parser-oriented sequence:

- **Revision 1064** — LALR parser and CFG for ASN.1 notation
- **Revision 1069** — parse tree
- **Revision 1070** — parse-tree visitor
- **Revision 1072** — ASN.1 parser usertype applied
- **Revision 1087** — `lalr1_parser` import
- **Revision 1088** — CFG for ASN.1 module
- **Revision 1089** — context-aware parser switching pattern
- **Revision 1090** — GLR parser and integrated CFG work covering ASN.1 notation, module, parameterized constructs, and information object class
- **Revision 1091** — CFG for ASN.1 information object class
- **Revision 1093** — CFG for ASN.1 extension marker versions 1 and 2.
- **Revision 1094** — parser-table binary layout and external table import.
- **Revision 1095** — build infrastructure changes supporting the parser-table workflow.
- **Revision 1096** — graph-structured stack (GSS) support for GLR and parse-tree construction fixes.
- **Revision 1097** — loader begins parsing file/memory input to a `parse_tree` (first step).
- **Revision 1099** — `IMPORTS`, `EXPORTS`, module linkage, `resolve()` and `is_resolvable()` are exercised in the module path.
- **Revision 1100** — shared ASN.1 knowledge and parser/publisher providers move under `asn1_advisor` (renamed from `asn1_resource`).
- **Revision 1102** — `asn1_runtime`/`asn1_runtime_context` are renamed to `asn1_module`/`asn1_module_context`; parameterized assignment/type/value grammar is extended and parser tables move to revision 2.
- **Revision 1103** — `asn1_publisher` fixes `TypeAssignment` semantic publication.

The important direction is parser selection at a stable semantic boundary, not a simple LALR-to-GLR replacement story. The GSS and parse-tree fixes from 1096 support the GLR path; by 1099–1103, the module path exercises GLR parsing through semantic publication and module resolution. The two parser mechanisms and their provider/configuration paths should remain explicit in the explanation.

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

LALR and GLR are mechanisms inside the first step. They are important for the current experiment, but the reason for the parser work is the boundary it creates for semantic construction.

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

The currently integrated ASN.1 runtime path is:

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

`asn1_module::add_schema()` currently creates an `asn1_parser` configured for GLR and passes the resulting parse tree through the shared `asn1_publisher`. Parser instances are supplied through `asn1_advisor`; LALR(1) and GLR remain selectable paths rather than one universal parser object.

### GLR path

The GLR work is currently an experimental path:

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

The purpose of the experiment is to make the grammar itself more expressive where a deterministic LALR table would otherwise require grammar-specific conflict avoidance or restructuring.

### Graph-structured stack

Revision 1096 introduces a graph-structured stack (GSS) for the GLR path. Instead of treating every parser branch as an independent linear stack, the GSS allows stack paths to share nodes while preserving multiple parent paths. This provides the structure needed for GLR reductions and path reconstruction without changing the production `asn1_module` parser from LALR.

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
   current          study
    runtime         path
```

At Revision 1103, the unified CFG and its parser providers feed a module path that selects GLR for `add_schema()`. Grammar coverage and semantic coverage are not identical: parameterized productions exist, but full parameter binding/substitution/instantiation is not yet complete.

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

Publisher coverage must track grammar coverage, but recognition and semantic instantiation are distinct. Module and TypeAssignment publication are exercised; parameterized productions have grammar/handler work, while complete parameter binding, substitution, and instantiated-object behavior remain unfinished.

### Context-aware parser switching

Revision 1089 introduced a context-aware parser switching pattern. The relevant idea is that parser behavior can be selected from grammar/context information rather than hard-coding one parser mechanism for every language fragment.

This is useful for the current study because LALR remains the established runtime path while GLR can be exercised against the broader grammar without prematurely replacing the existing path.

## Flow

The current and experimental paths should be kept visually separate:

```text
                    ASN.1 notation
                          │
                          ▼
                    lexical analysis
                          │
                          ▼
                  integrated CFG model
                     │           │
             current │           │ experimental
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

For the existing runtime:

```text
asn1_module::add_schema()
        ↓
parse()
        ↓
lalr1_parser
        ↓
parse_tree
        ↓
asn1_builder / asn1_publisher
        ↓
asn1_object*
```

For the next study direction:

```text
integrated CFG validation
        ↓
GLR parser application
        ↓
multiple parse paths where required
        ↓
semantic construction policy
        ↓
publisher expansion
        ↓
loader integration later
```

The loader path has advanced since Revision 1097: input can flow through parser and publisher into module-level information, including IMPORTS/EXPORTS and resolvability checks. Parameterized semantic instantiation remains a separate incomplete area.

## Study & Verification

The parser study should verify the layers independently before combining them:

1. **CFG coverage** — confirm that notation, module, parameterized constructs, information-object-class, and extension-marker grammar can be represented by the intended unified CFG.
2. **LALR baseline** — preserve the existing ASN.1 runtime parser behavior while the new grammar is being explored.
3. **GLR experiment** — exercise the broader grammar and observe where multiple parse paths are produced.
4. **Semantic construction** — determine how each parse result maps to semantic values and eventually to `asn1_object*` or related runtime structures.
5. **Publisher expansion** — add handlers only as grammar coverage produces new semantic categories.
6. **Loader integration** — extend the new loader parser-entry step toward Module construction and runtime registration after the parser and publisher boundaries are stable.

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

At Revision 1103:

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
