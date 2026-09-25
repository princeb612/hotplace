# ASN.1 Runtime

## Context

`asn1_runtime` is the runtime environment in which ASN.1 semantic definitions, references, schemas, and values are registered and used.

It is not merely a container for parser output.

Its current responsibilities span:

```text
schema input
    ↓
parsing
    ↓
semantic construction
    ↓
schema registration
    ↓
name lookup
    ↓
reference resolution
    ↓
runtime linkage
    ↓
typed value processing
```

The runtime therefore forms the bridge between the semantic ASN.1 model and actual encode/decode use.

## Why a runtime environment is needed

Constructing one `asn1_object` is not enough to use an ASN.1 module. Real schemas contain names, references, dependencies, module-level policy, and runtime values. Those relationships need an environment in which they can be registered and resolved.

So the runtime sits one step beyond semantic construction:

```text
publisher
   ↓
semantic objects
   ↓
asn1_runtime
   ├── names / definitions
   ├── references / dependencies
   ├── module policy
   └── runtime values
```

This is why `define()`, `refer()`, `add()`, `resolve()`, and `add_schema()` should be read as different stages of the runtime model rather than interchangeable APIs.

## Conceptual

### `asn1_object` and `asn1_runtime` are different levels

An `asn1_object` represents one semantic object.

For example:

```text
Person
  │
  ▼
SEQUENCE
  ├── name : VisibleString
  └── age  : INTEGER DEFAULT 20
```

`asn1_runtime` provides the environment in which named definitions and their relationships are registered:

```text
asn1_runtime
  │
  ├── Person
  ├── Address
  └── Employee
```

The runtime therefore provides a namespace/schema environment rather than being the semantic object itself.

### Definition and reference are different concepts

The semantic model distinguishes:

```text
define()
    named definition → semantic object

refer()
    named reference → another definition
```

Runtime registration is a separate operation:

```text
define / refer
       ↓
asn1_runtime::add()
       ↓
dictionary
```

Likewise:

```text
asn1_runtime::add_schema()
```

is a higher-level path that parses schema text and invokes semantic construction before registration.

These concepts should not be collapsed into one operation.

## Current construction path

Revision 1090 already contains a working schema-to-runtime path through `add_schema()`:

```text
schema text
    ↓
asn1_runtime::parse()
    ↓
parse_tree
    ↓
asn1_publisher::build()
    ↓
asn1_object
    ↓
asn1_runtime::add()
    ↓
dictionary / type registry
```

`add_schema()` also keeps the original schema text associated with the resulting object through the runtime schema map.

This is the current primitive from which future Module-level loading can be built.

## Structural

| Component | Role |
| --- | --- |
| `_dictionary` | Name → semantic object lookup |
| `_types` | Registered semantic objects |
| `_schema` | Original schema text associated with registered objects |
| `_values` | Runtime values associated with semantic objects |
| `_name` | Runtime environment name |
| `_automatic` | Module-level automatic-tagging mode |
| `get(name)` | Named schema/type lookup |
| `add(object)` | Register an already constructed semantic object |
| `add_schema(schema)` | Parse, publish, and register a schema definition |
| `resolve()` | Build dependency relationships between registered definitions |
| `is_resolvable()` | Check whether references can be resolved |
| `update_linkage()` | Resolve referenced objects and propagate linkage such as constructed/explicit behavior |
| `read()` | Strongly typed runtime decoding using registered schema |
| `read_weakly_typed()` | Schema-less/weakly typed decoding |

## Namespace and dependency environment

Suppose a Module contains:

```text
Address ::= ...
Person ::= SEQUENCE {
    address Address
}
Employee ::= Person
```

The runtime environment can be viewed as:

```text
asn1_runtime
│
├── Address
│
├── Person
│    └── reference → Address
│
└── Employee
     └── reference → Person
```

`resolve()` traverses these references and builds a dependency graph. The graph is then topologically ordered so that the dependency relationship can be checked and consumed in an appropriate order.

This gives the runtime a meaning beyond simple name lookup:

```text
name
  ↓
definition
  ↓
references
  ↓
dependency graph
  ↓
resolved environment
```

`update_linkage()` is a separate semantic/runtime step. For a reference, it can locate the referenced definition, clone the referenced object when necessary, and propagate linkage information through tagged parents.

## Module-level tagging

`asn1_runtime` already has a runtime setting for the Module-level automatic-tagging policy.

The conceptual distinction is:

```text
Module policy
    ├── EXPLICIT
    ├── IMPLICIT
    └── AUTOMATIC
```

This is different from an individual `asn1_tagged_type`.

A tagged type represents a semantic tag relationship on a particular object. The runtime's automatic-tagging state represents a Module-level environment policy.

The default runtime state is explicit tagging.

Future Module loading should read the Module header and establish this policy before completing Module schema construction.

## Runtime values

The runtime also associates values with schema objects:

```text
asn1_object
     │
     └── asn1_value
```

This allows the same environment to support:

```text
schema
  ↓
typed object
  ↓
runtime value
  ↓
DER encode/decode
```

This is why `asn1_runtime` should be understood as the environment shared by schema interpretation and runtime value processing.

## Runtime usage

The runtime becomes useful after schema registration. The current tests show a clear distinction between **building a semantic schema** and **using that schema to process a value**.

A typical strongly typed path is:

```text
registered schema
      ↓
lookup by name
      ↓
asn1_strongly_typed::read()
      ↓
asn1_value associated with the schema
      ↓
ASN.1 value tree / fields
```

`asn1_runtime::read(name, ...)` is therefore a runtime operation over an already registered semantic schema. It resolves the named schema, obtains or creates its associated `asn1_value`, parses the input byte stream, and walks the schema while decoding the matching fields.

The corresponding test pattern in `testcase_basic3.cpp` is:

```text
ASN.1 schema text
      ↓
add_schema()
      ↓
semantic schema registered in runtime
      ↓
read(name, DER)
      ↓
runtime value
      ├── notation(name)
      └── publish(name, DER)
```

The test compares the reconstructed notation with the expected schema text and compares the re-encoded DER with the original input. This makes the test a **schema interpretation + value round-trip** check rather than a parser-only check.

### Manually constructed schema vs reconstructed schema

`test_decode_strongly_typed1()` also builds equivalent semantic objects directly with `asn1_referenced_type::define()` and `refer()`, while separately registering the ASN.1 notation through `add_schema()`. The manually constructed object is used as the expected semantic model/test vector, while the runtime exercises the schema reconstructed from notation.

The important relationship is therefore:

```text
direct semantic construction        ASN.1 notation
            │                              │
            ▼                              ▼
     expected model                 parse + publish
            │                              │
            └──────────────┬───────────────┘
                           ▼
                    runtime behavior
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
              notation              DER
```

This verifies that the parser/publisher path can produce a semantic model usable in the same runtime processing path as a manually constructed model.

### Reference resolution before value processing

`test_resolve_dependencies()` demonstrates another prerequisite for runtime use. A set of definitions can be registered independently, then the runtime can calculate the dependency order for the whole environment or for a selected definition.

```text
registered definitions
        ↓
reference graph
        ↓
resolve()
        ↓
dependency order
        ↓
is_resolvable() / linkage
        ↓
value processing
```

An unresolved definition does not invalidate unrelated resolved definitions. The test adds an object containing missing references and verifies that the unresolved object is reported while an already-resolved object remains resolvable.

This is important for the future Module loader: loading and registration can establish the environment first, while resolution provides a separate validation/linkage step over the resulting namespace.

### Weakly typed and strongly typed processing

The runtime exposes two distinct decoding paths:

```text
DER / byte stream
      │
      ├── read(name, ...)
      │       ↓
      │   strongly typed
      │   schema-directed value
      │
      └── read_weakly_typed(...)
              ↓
          weakly typed
          value interpretation
```

The distinction is not another schema-definition mechanism. It is a difference in how an input value is interpreted: strongly typed decoding starts from a named registered schema, while weakly typed decoding can interpret the encoded structure without selecting a named schema first.

### Runtime round trip

The resulting runtime usage can be summarized as:

```text
                 schema environment
                        │
                        ▼
                    named type
                        │
                        ▼
                 decode input value
                        │
                        ▼
                  asn1_value
                   │         │
                   ▼         ▼
              notation     DER encode
```

This closes the conceptual path from semantic construction to actual runtime behavior. The schema is no longer just a parser product; it becomes the instruction set used to interpret and produce encoded ASN.1 values.

## Flow

The current single-schema path is:

```text
ASN.1 schema text
       ↓
      parse
       ↓
   parse_tree
       ↓
   publisher
       ↓
  semantic object
       ↓
      add
       ↓
 runtime dictionary
```

The future Module-level path is:

```text
ASN.1 Module
       ↓
     loader
       ↓
Module metadata
       │
       ├── name
       ├── tagging policy
       └── assignments
              ↓
       semantic construction
              ↓
       runtime registration
              ↓
         asn1_runtime
              ↓
       namespace / environment
              ↓
       resolve / linkage
```

## Study & Verification

The runtime tests and examples demonstrate several layers of use.

A manually constructed schema can be registered with `define()` and `refer()` and then added to a runtime.

A schema string can be processed through `add_schema()`.

Once definitions are registered, the runtime can:

- look up a named schema,
- inspect notation,
- resolve references,
- update semantic linkage,
- decode strongly typed values,
- decode weakly typed values,
- publish notation or DER output.

The `case24_type2` style experiments are especially useful as semantic-construction verification: they manually build the runtime representation that the future parser/publisher/loader pipeline is expected to produce.

## Status

The runtime layer is substantially more complete than the loader layer.

Current:

```text
[x] parser integration
[x] parse_tree input
[x] publisher integration
[x] semantic object registration
[x] name lookup
[x] schema retention
[x] reference dependency resolution
[x] linkage update
[x] typed runtime processing
[~] broader Module-level semantics
```

The Module-level environment is therefore partly prepared in the runtime itself, but the orchestration that reads a complete `.asn1` Module and constructs this environment is not yet implemented by `asn1_loader`.

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
  ├── schema registry
  ├── namespace
  ├── dependency resolution
  └── runtime values
       ↑
     loader
```

The loader is the next layer above this runtime environment.
