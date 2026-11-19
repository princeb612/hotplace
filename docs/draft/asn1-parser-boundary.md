# ASN.1 Parser Boundary — Draft

> Source base : Revision 1132

## Why preserve this

Recent ASN.1 work can easily be misread as one continuous move from grammar to runtime. The current state is separated into active LALR/GLR parser paths, parser-table infrastructure, and bounded semantic/runtime coverage.

## Current boundary

```text
ASN.1 grammar coverage
        │
        ▼
 parser provider selection
        │
        ├── LALR notation-oriented path
        │
        └── GLR module/schema path
              (asn1_module::add_schema)
                    │
                    ▼
             grammar validation
```

GLR is no longer only an experimental path: `asn1_module::add_schema()` selects GLR for module/schema construction. LALR remains available through the notation-oriented parser providers. These are distinct active entry paths; neither should be described as a universal replacement for the other.

## Revision 1094 infrastructure boundary

The integrated grammar produced an ACTION table approaching 4 MB and exposed a compile-time scale problem. The resulting infrastructure direction is:

```text
grammar
  ↓
parser table generation
  ↓
dedicated external table file
  ↓
import()
  ↓
parser execution
```

This is a parser infrastructure problem, not a semantic ASN.1 step. `lalr_parser::import()` is the existing conceptual anchor for loading a prebuilt table.

## Semantic sequence

The current source path separates syntax loading, semantic publication, and module storage:

```text
ASN.1 file / memory
        ↓
asn1_loader
        ↓
parse_tree
        ↓
asn1_publisher
        ↓
asn1_module / asn1_modules
        ↓
semantic runtime objects
```

The parser-table scale question remains a separate infrastructure concern. The compiler is a downstream design target, not part of this currently exercised path.

The intended long-term architecture remains **runtime → loader → compiler**, not runtime → compiler → loader: the runtime establishes the semantic object/environment model, the loader maps ASN.1 modules/files into that environment, and a compiler can consume the semantic model for C++ source generation. This intended layering is distinct from the current parser → publisher → module execution path shown above.

## Status caution

The loader is no longer stub-level: `asn1_loader::load_file()` and `load()` tokenize/parse file or memory input into a `parse_tree`; publisher and module paths provide semantic reconstruction, including IMPORTS/EXPORTS and reference resolution. Parameterized instantiation is implemented for selected tested forms, not all ASN.1 parameter patterns. The compiler directory remains at the design/documentation stage; no compiler implementation source is present in the Revision 1132 tree.

## Candidate destination

- Parser README: grammar/table infrastructure boundary.
- ASN.1 README: semantic construction and runtime boundary.
- ASN.1 loader README: loader's intended position once implementation is mature.


## Revision 1103–1132 note

The boundary has moved since this draft was written: `asn1_module::add_schema()` currently selects GLR, and the loader/parser/publisher flow now exercises module-level IMPORTS/EXPORTS and reference resolution. Revision 1102 renamed the former `asn1_runtime`/`asn1_runtime_context` classes to `asn1_module`/`asn1_module_context`; Revision 1103 fixed `TypeAssignment` semantic publication. Revisions 1123–1125 add parameterized definition reconstruction, visitor-state propagation, actual type/value argument collection, and move-aware specialization. `test_parameterized2()` and `test_parameterized3()` are active and verify selected `FRAME`/MyPacket and module reconstruction paths. Parameterized grammar coverage remains broader than the semantic forms proven by these tests. Treat the older diagram above as a historical boundary sketch, not a current claim that GLR is unintegrated.
