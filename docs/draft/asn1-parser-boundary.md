# ASN.1 Parser Boundary — Draft

## Why preserve this

Recent ASN.1 work can easily be misread as one continuous move from grammar to runtime. The current state is actually separated into experimental grammar work, parser-table infrastructure, and semantic/runtime construction.

## Current boundary

```text
ASN.1 grammar coverage
        │
        ▼
 parser / grammar experiments
        │
        ├── LALR production path
        │
        └── GLR experimental path
                    │
                    ▼
             grammar validation
```

The GLR work is currently an experimental grammar path. It must not be described as having replaced the LALR production parser or as already driving semantic construction.

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

Only after grammar/table scale is usable does the next semantic step become useful:

```text
[grammar recognized?]
        ↓
[parser table usable at actual scale?]
        ↓
[semantic object can be built?]
        ↓
asn1_module
        ↓
loader
        ↓
compiler
```

The intended architecture is **runtime → loader → compiler**, not runtime → compiler → loader.

The runtime establishes the semantic object/environment model. The loader will map ASN.1 modules/files into that environment. The compiler can then consume the semantic model for C++ source generation.

## Status caution

The loader remains incomplete/stub-level in the current source context. The compiler is a future consumer of the semantic model. These should not be described as completed subsystems merely because their architectural position is already clear.

## Candidate destination

- Parser README: grammar/table infrastructure boundary.
- ASN.1 README: semantic construction and runtime boundary.
- ASN.1 loader README: loader's intended position once implementation is mature.


## Revision 1103 note

The boundary has moved since this draft was written: `asn1_module::add_schema()` currently selects GLR, and the loader/parser/publisher flow now exercises module-level IMPORTS/EXPORTS and reference resolution. Revision 1102 renamed the former `asn1_runtime`/`asn1_runtime_context` classes to `asn1_module`/`asn1_module_context`; Revision 1103 fixed `TypeAssignment` semantic publication. Parameterized grammar recognition is broader than its currently implemented semantic instantiation. Treat the older diagram above as a historical boundary sketch, not a current claim that GLR is unintegrated.
