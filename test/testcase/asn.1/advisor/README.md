# ASN.1 Advisor

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1102 (working tree)
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

`asn1_advisor` is the ASN.1 shared knowledge/provider component. It retains the former resource/dictionary role for ASN.1 entities, classes, and tagging modes, while also providing shared parser and publisher instances needed by the runtime-facing ASN.1 path.

The name reflects the role visible in the current source: this component does not merely expose static resources. It advises the rest of the ASN.1 implementation about entity names/permissions and supplies prepared parser/publisher objects.

## Responsibilities

```text
asn1_advisor
    |
    +-- ASN.1 entity dictionary
    |     +-- entity id <-> notation name
    |     `-- primitive / constructed / both permission
    |
    +-- class dictionary
    |     +-- UNIVERSAL
    |     +-- APPLICATION
    |     +-- PRIVATE
    |     `-- CONTEXT
    |
    +-- tagging/default mode dictionary
    |     +-- AUTOMATIC
    |     +-- IMPLICIT
    |     +-- EXPLICIT
    |     +-- DEFAULT
    |     `-- OPTIONAL
    |
    +-- shared asn1_publisher
    |
    +-- LALR(1) notation parser providers
    |     +-- build
    |     `-- import
    |
    `-- GLR parser providers
          +-- build
          `-- import
```

The provider objects are stored by the singleton and are prepared lazily. This gives the parser/runtime path a common place to obtain ASN.1-specific parser and publication resources without constructing those objects for every operation.

## Entity and notation information

`resource_asn1_entities[]` remains the source table for built-in ASN.1 entity information. `doload_resource()` materializes the lookup dictionaries used by:

- `get_component_entity_name()`
- `get_entity_name()`
- `get_entity()`
- `get_perm()`
- `get_class_name()` / `get_class()`
- `nameof_mode()` / `valueof_mode()`

The table therefore remains a resource source internally, but the owning component is now `asn1_advisor` and its public role is broader than the former `asn1_resource` dictionary.

## Shared publisher

`get_publisher()` prepares and returns the advisor-owned publisher:

```text
asn1_advisor::get_publisher()
          |
          v
    asn1_publisher::prepare()
          |
     +----+----+
     |         |
     v         v
prepare_    prepare_
basics()   constraints()
```

The same publisher instance is reused by the ASN.1 parser/runtime path. This keeps grammar-handler preparation outside individual parser instances.

## Parser providers

The advisor also owns four parser objects:

```text
get_notation_parser_by_build()
get_notation_parser_by_import()
get_parser_by_build()
get_parser_by_import()
```

The distinction preserves the two parser roles used by the ASN.1 implementation: notation parsing and the grammar/parser path used by the current runtime-facing flow. The source currently selects the imported GLR parser for `asn1_parser` while the other prepared parser instances remain available through the advisor.

## Lazy initialization

`get_instance()` calls `load_resource()`. The resource tables are populated once under `_lock`, after which the singleton owns the dictionaries and provider objects for subsequent calls.

```text
get_instance()
      |
      v
load_resource()
      |
      +-- entity/class/mode dictionaries
      |
      +-- publisher
      |
      `-- parser providers
```

The naming `load_resource()` is retained internally because the advisor still materializes static ASN.1 resource tables. The externally visible component identity is nevertheless `asn1_advisor`.

## Related source

- `sdk/io/asn.1/asn1_advisor.hpp`
- `sdk/io/asn.1/advisor/asn1_advisor.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/parser/lalr1_parser.*`
- `sdk/io/parser/glr_parser.*`

## Related tests

- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`

The tests normally reach advisor functionality through parser, publisher, runtime, and loader operations rather than treating the advisor as an independent application-level API.
