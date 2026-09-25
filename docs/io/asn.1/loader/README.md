# ASN.1 Loader

## Context

`asn1_loader` is the planned entry point for turning an `.asn1` source file or memory buffer into a Module-level `asn1_runtime` environment.

The loader is not intended to replace the parser or publisher.

Its role is orchestration:

```text
.asn1
  ↓
loader
  ↓
Module
  ↓
semantic construction
  ↓
asn1_runtime
```

The parser and semantic construction layers are being developed first so that the loader can eventually compose them rather than reimplement them.

## Target responsibility

The loader begins at the Module boundary.

A complete load operation is expected to establish:

```text
Module
├── module name
├── module-level tagging policy
├── assignments
├── definitions
├── references
└── other Module semantic information
        ↓
asn1_runtime
```

The resulting runtime is an environment in which the Module's schemas can be looked up, resolved, and used for runtime value processing.

## Current state

The current implementation intentionally starts the loader interface but does not yet implement Module construction.

`asn1_loader::load_file()` currently handles file input and forwards the contents to `load()`.

`asn1_loader::load()` is currently a stub.

Therefore the following diagram describes the **target architecture**, not the current implementation:

```text
.asn1 file
    ↓
asn1_loader
    ↓
Module parsing
    ↓
Module metadata
    ├── name
    └── tagging mode
    ↓
semantic construction
    ↓
schema registration
    ↓
asn1_runtime
```

The existing working lower-level path is currently provided by `asn1_runtime::add_schema()`:

```text
schema text
    ↓
parse
    ↓
parse_tree
    ↓
asn1_publisher
    ↓
asn1_object
    ↓
add()
```

The loader will eventually orchestrate this kind of operation at Module scope.

## Why Module is the loader boundary

A single ASN.1 type is not the complete runtime environment.

For example:

```asn1
PersonModule DEFINITIONS ::= BEGIN

Address ::= SEQUENCE {
    city VisibleString
}

Person ::= SEQUENCE {
    name VisibleString,
    address Address
}

Employee ::= Person

END
```

The loader should treat this as one Module:

```text
PersonModule
│
├── Address
├── Person
└── Employee
```

rather than as three unrelated schema strings.

This matters because definitions can reference one another and because Module-level policies, such as tagging mode, affect the interpretation of contained definitions.

## Module → runtime

The intended construction is:

```text
                  .asn1
                    │
                    ▼
                 loader
                    │
              ┌─────┴─────┐
              │            │
        Module metadata   assignments
              │            │
       tagging policy     publisher
              │            │
              │       semantic objects
              │            │
              └─────┬──────┘
                    ▼
              asn1_runtime
                    │
          ┌─────────┼─────────┐
          │         │         │
       namespace  schema   environment
          │         │         │
          └─────────┼─────────┘
                    ▼
             resolve/linkage
```

This is the point at which the runtime becomes a usable Module namespace/environment rather than merely a collection of individually constructed objects.

## Tagging policy

Module-level tagging is one of the first pieces of information the loader must establish.

The Module header can specify:

```text
EXPLICIT TAGS
IMPLICIT TAGS
AUTOMATIC TAGS
```

The loader should interpret this as Module environment state and configure the resulting `asn1_runtime` accordingly.

This should remain distinct from explicit tagged-type construction:

```text
Module tagging policy
        ≠
individual tagged type
```

The first is an environment rule. The second is part of an individual semantic object.

## Schema registration

Once semantic construction produces definitions, the loader must register them into the runtime environment.

Conceptually:

```text
definition
    ↓
asn1_object
    ↓
asn1_runtime::add()
    ↓
dictionary
```

References are not definitions. A reference points to another named definition:

```text
Person
  └── address → Address
```

After registration, the runtime can perform:

```text
lookup
  ↓
resolve
  ↓
dependency graph
  ↓
linkage
```

This distinction keeps loader orchestration separate from semantic construction.

## Future loading flow

The intended end-to-end flow is:

```text
                 .asn1
                   │
                   ▼
              asn1_loader
                   │
                   ▼
                Module
                   │
          ┌────────┼────────┐
          │        │        │
        name      tags   assignments
          │        │        │
          │        │        ▼
          │        │    parser
          │        │        ↓
          │        │    parse_tree
          │        │        ↓
          │        │    publisher
          │        │        ↓
          │        │  semantic objects
          │        │        │
          └────────┴────────┘
                   │
                   ▼
             asn1_runtime
                   │
                   ├── definitions
                   ├── references
                   ├── constraints
                   ├── namespace
                   └── values
```

The exact internal orchestration can evolve. The stable architectural contract is that the loader owns the Module boundary while parser and publisher own syntax and semantic construction.

## Study & Verification

Current loader verification should remain intentionally small until the lower-level parser and semantic construction experiments stabilize.

The useful milestones are:

1. Load a `.asn1` buffer.
2. Identify the Module.
3. Extract Module-level tagging policy.
4. Construct semantic definitions through the existing parser/publisher path.
5. Register definitions in an `asn1_runtime`.
6. Verify named lookup.
7. Verify reference resolution.
8. Verify linkage for tagged/reference combinations.
9. Use the resulting runtime for typed encode/decode.

The current parser experiments are therefore not separate from the loader work. They are prerequisites for making these milestones reliable.

## Status

```text
[x] loader interface exists
[x] file input entry point exists
[x] memory input entry point exists
[x] lower-level runtime schema construction exists
[x] semantic publisher exists
[~] integrated ASN.1 grammar / GLR experiments
[~] Module semantic model
[ ] Module extraction in loader
[ ] Module-level tagging configuration in loader
[ ] Module → asn1_runtime construction
[ ] loader-level reference/linkage orchestration
[ ] end-to-end .asn1 loader tests
```

The important current state is:

> **The loader has begun, but the parser/semantic front end is being prepared first.**

Once that front end is sufficiently stable, the loader becomes the layer that turns an `.asn1` Module into a configured `asn1_runtime` namespace/environment.

## Related topics

```text
parser
  ↓
parse_tree
  ↓
asn1_publisher
  ↓
semantic object
  ↓
asn1_runtime
  ↑
loader
  ↑
.asn1 Module
```

The loader is therefore the beginning of the Module-level runtime phase, not another parser implementation.


## Runtime usage after loading

The loader's useful result is not merely a collection of parsed assignments. Its result is an `asn1_runtime` environment that can be resolved and used for value processing:

```text
.asn1 Module
     ↓
   loader
     ↓
asn1_runtime
     ↓
resolve / linkage
     ↓
lookup named type
     ↓
read / publish
```

This is why Module metadata and semantic definitions must be established before the runtime is handed to encode/decode operations.
