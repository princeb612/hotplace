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
asn1_runtime
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
