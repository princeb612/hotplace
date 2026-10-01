# ASN.1 Runtime

`asn1_runtime` is the runtime layer that turns ASN.1 notation and DER/BER byte streams into the project's ASN.1 object model, and can publish that model back to ASN.1 notation or DER.

This layer sits between the ASN.1 syntax/parser side and the semantic ASN.1 types under `basic/`. It is also the point where weakly typed decoded data can be promoted into semantic objects and where strongly typed schema definitions are resolved and decoded.

## Role in hotplace

```text
ASN.1 notation
      |
      v
asn1_parser / parser
      |
      v
parse_tree
      |
      v
asn1_builder / asn1_publisher
      |
      v
asn1_object semantic model
      |
      +-----------------------------+
      |                             |
      v                             v
 weakly typed DER decode       strongly typed decode
 asn1_node tree                schema/reference lookup
      |                             |
      +-------------+---------------+
                    |
                    v
               asn1_runtime
                    |
          +---------+---------+
          |                   |
          v                   v
       notation              DER
```

The important point is that `asn1_runtime` is not itself the ASN.1 grammar parser. `asn1_parser` handles the notation-to-parse-tree step; the runtime layer builds, stores, resolves, decodes, and publishes the resulting semantic objects.

## Main components

### `asn1_runtime`

`asn1_runtime` owns a collection of named ASN.1 objects/types and provides the public runtime operations.

Important operations include:

- `add_schema()` — parse and add an ASN.1 schema definition.
- `add()` / `set()` / `get()` — manage runtime objects and their values.
- `parse()` — parse ASN.1 notation through the runtime parser path.
- `read()` — decode a named type from a byte stream.
- `read_weakly_typed()` — decode without requiring a fully resolved semantic type first.
- `notation()` — publish a runtime object as ASN.1 notation.
- `publish()` — encode a runtime object as DER/binary data.
- `resolve()` / `is_resolvable()` — inspect and resolve referenced-type dependencies.
- `update_linkage()` — propagate linkage information through the object hierarchy, including constructed/tag relationships.

The runtime therefore acts as both a **schema/object registry** and the central entry point for encode/decode operations.

### `asn1_builder`

`asn1_builder` converts parser output into semantic `asn1_object` instances. It provides helpers for built-in entities, tags, named entities, and construction from a `parse_tree`.

The builder is especially important for the reverse direction used by the tests:

```text
ASN.1 notation
    -> parse_tree
    -> asn1_builder
    -> asn1_object
```

This is different from merely decoding a DER stream. It reconstructs the semantic type/object model represented by the notation.

### `asn1_publisher`

`asn1_publisher` performs semantic construction from a parse tree using handlers for ASN.1 grammar constructs. It has separate preparation for basic constructs and constraints.

In practice, the publisher/builder pair forms the semantic-construction side of the runtime parser flow.

### `asn1_weakly_typed`

Weak decoding starts from the DER/BER structural representation rather than a completely resolved schema.

```text
DER stream
   |
   v
asn1_node tree
   |
   |  structural information
   |  identifier / P-C bit / length / raw value
   v
asn1_weakly_typed::transform()
   |
   v
asn1_object semantic representation
```

The implementation first reconstructs semantic objects from the structural nodes, binds them to parents/containers/tags, and then injects leaf values. This is useful when the stream must be interpreted before a complete strongly typed schema is available.

`testcase_basic2.cpp` exercises this path extensively, including IMPLICIT/EXPLICIT tagging, nested containers, `SEQUENCE OF`, `SET OF`, high tag numbers, and DER round trips.

### `asn1_strongly_typed`

Strong decoding starts with a named schema/type already registered in `asn1_runtime`.

```text
schema definitions
      |
      v
asn1_runtime
      |
 named type/reference resolution
      |
      v
DER stream -> semantic object
```

`asn1_strongly_typed::read()` selects a named runtime object and decodes the stream according to its semantic structure.

The tests demonstrate both simple referenced types and nested/tagged types such as:

```text
Type1 ::= VisibleString
Type2 ::= [APPLICATION 3] IMPLICIT Type1
Type3 ::= [2] EXPLICIT Type2
```

and constructed values such as `SEQUENCE` with named members.

## Reference and linkage model

A major part of the runtime is resolving named ASN.1 definitions.

The semantic layer distinguishes between a referenced type definition and a reference to another type. Typical construction is:

```cpp
asn1_referenced_type::define("Person", new asn1_sequence(...));
asn1_referenced_type::refer("Person");
```

A definition owns the semantic object, while a reference identifies another definition. `asn1_runtime::resolve()` walks these dependencies and `is_resolvable()` reports whether the required definitions are available.

`update_linkage()` then updates relationships in the constructed object hierarchy. This is important for tag and constructed-bit propagation when nested or explicitly/implicitly tagged types are involved.

## Encode/decode round trip

The runtime is designed around a useful verification cycle:

```text
schema / notation
       |
       v
semantic ASN.1 object
       |
       +---- publish() ----> DER
       |                       |
       |                       v
       +<----- read() <---- decoded object
       |
       +---- notation() ----> ASN.1 notation
```

`testcase_basic3.cpp` verifies this by registering schemas, reading DER, publishing ASN.1 notation and DER again, and comparing the regenerated representation with the expected schema and original DER stream.

## Constraints

`asn1_builder` is also used by the constraints tests to construct semantic types with constraint information. `testcase_constraints.cpp` covers integer, real, string, sequence/set-of and related subtype constraints.

This makes the runtime layer the bridge between the parser's constraint notation and the semantic type objects that enforce or carry those constraints.

## Related source

- `sdk/io/asn.1/runtime/asn1_runtime.*`
- `sdk/io/asn.1/runtime/asn1_parser.*`
- `sdk/io/asn.1/runtime/asn1_builder.*`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/runtime/asn1_weakly_typed.*`
- `sdk/io/asn.1/runtime/asn1_strongly_typed.*`
- `sdk/io/asn.1/basic/semantic/`
- `sdk/io/asn.1/basic/structural/`

## Related tests

- `test/testcase/asn.1/testcase_basic2.cpp` — weakly typed transformation and semantic construction cases.
- `test/testcase/asn.1/testcase_basic3.cpp` — strongly typed decode, reference resolution, and parser/runtime integration.
- `test/testcase/asn.1/testcase_constraints.cpp` — semantic construction with ASN.1 constraints.
- `test/testcase/asn.1/runtime/testcase_parser.cpp` — runtime parser path.
- `test/testcase/asn.1/runtime/testcase_publish.cpp` — runtime publishing path.

## Related areas

- `sdk/io/asn.1/basic/` — ASN.1 semantic/structural type model.
- `sdk/io/asn.1/loader/` — loading ASN.1 modules into the runtime flow.
- `sdk/io/asn.1/compiler/` — future/source-generation direction.
- `sdk/io/parser/` — grammar parsing infrastructure.
