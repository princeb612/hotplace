# Parser — Grammar to Parse Structure

**Edition 1 · Revision 1090**

## Context

The parser work is currently extending a working notation-oriented path toward a broader grammar model. LALR and GLR are mechanisms used to explore that problem; the reader-facing boundary is simpler: turn language structure into a parse result that later stages can interpret.

This document owns the parser question:

> How does a grammar become an executable parser, and how does the parser expose enough structure for semantic construction?

The current ASN.1 runtime path remains LALR-based. The GLR implementation is being studied as the next parser mechanism for the broader ASN.1 grammar; it is not yet the parser used by `asn1_runtime`.

## History

The CHANGELOG gives the following parser-oriented sequence:

- **Revision 1064** — LALR parser and CFG for ASN.1 notation
- **Revision 1069** — parse tree
- **Revision 1070** — parse-tree visitor
- **Revision 1072** — ASN.1 parser usertype applied
- **Revision 1087** — `lalr1_parser` import
- **Revision 1088** — CFG for ASN.1 module
- **Revision 1089** — context-aware parser switching pattern
- **Revision 1090** — GLR parser and integrated CFG work covering ASN.1 notation, module, parameterized constructs, and information object class.

The important direction is not a replacement of LALR by GLR at Revision 1090. It is an experiment to determine whether a broader ASN.1 grammar can be represented and parsed without forcing every ambiguity into the existing deterministic path.

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

`asn1_runtime` contains a `lalr1_parser`, imports the ASN.1 production/action/goto tables, and uses that parser when `add_schema()` parses notation.

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

At Revision 1090, the unified CFG is the study object. Its grammar coverage is broader than the current production runtime parser, which remains LALR-based.

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

As grammar coverage grows, publisher coverage must grow with it. This is why future semantic handlers are expected for module, parameterized, information-object-class, and related productions. Those handlers are a consequence of broader semantic coverage, not a function of GLR itself.

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
asn1_runtime::add_schema()
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

Loader integration is therefore a later stage. The existence of `asn1_loader` source files does not mean that the Revision 1090 parser experiment has already been absorbed into the loader architecture.

## Study & Verification

The parser study should verify the layers independently before combining them:

1. **CFG coverage** — confirm that notation, module, parameterized constructs, and information-object-class grammar can be represented by the intended unified CFG.
2. **LALR baseline** — preserve the existing ASN.1 runtime parser behavior while the new grammar is being explored.
3. **GLR experiment** — exercise the broader grammar and observe where multiple parse paths are produced.
4. **Semantic construction** — determine how each parse result maps to semantic values and eventually to `asn1_object*` or related runtime structures.
5. **Publisher expansion** — add handlers only as grammar coverage produces new semantic categories.
6. **Loader integration** — connect the stabilized semantic/runtime path to the loader after the parser and publisher boundaries are understood.

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

At Revision 1090:

- `asn1_runtime` still uses `lalr1_parser` for its ASN.1 parsing path.
- The parser layer contains both LALR and GLR implementations.
- The integrated CFG covers ASN.1 notation, module, parameterized constructs, and information object class. The current work is validating this grammar with the GLR path; this does not yet replace the LALR-based production runtime path.
- Context-aware parser switching has been explored as a way to keep parser selection dependent on grammar/context.
- GLR is currently the experimental mechanism being applied to validate the integrated CFG; it is not yet the production ASN.1 runtime parser.
- `asn1_publisher` remains the semantic-construction boundary. Broader grammar coverage is expected to require additional handlers.
- Loader integration is later work, after parser/semantic construction boundaries stabilize.

## Related topics

- [ASN.1 Semantic Construction](../../asn.1/README.md)
- `sdk/io/parser/cfg_grammar.*`
- `sdk/io/parser/lalr1_parser.*`
- `sdk/io/parser/glr_parser.*`
- `sdk/io/parser/parse_tree.*`
- `sdk/io/asn.1/runtime/asn1_runtime.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/loader/asn1_loader.*`
