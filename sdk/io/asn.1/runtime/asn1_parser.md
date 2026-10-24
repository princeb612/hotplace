## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1 Parser

## 1. Role

### Role in hotplace

```text
ASN.1 notation
      |
      v
 asn1_parser
      |
      +-- to_tokens() ----> parser_token[]
      |                         |
      |                         v
      |                  to_parsetree()
      |                         |
      |                         v
      |                    parse_tree
      |                         |
      +-----------------> to_result()
                                |
                                v
                         asn1_publisher
                                |
                                v
                       asn1_build_resultset
```

The class deliberately keeps three stages visible:

1. lexical conversion from notation to `parser_token` values;
2. grammar parsing from tokens to `parse_tree`;
3. semantic publication from the parse tree to `asn1_build_resultset`.

This separation is useful to the loader and tests because each boundary can be exercised independently.

## 2. Data Model

### Input and intermediate representations

- **Notation buffer:** source text supplied directly or by `asn1_loader`.
- **`parser_token` sequence:** generic parser tokens produced from ASN.1 lexical descriptions; comments are omitted and identifier-like lexical values are mapped to the ASN.1 identifier token.
- **`parse_tree`:** generic grammar result. It represents syntax and parser structure, not a fully reconstructed ASN.1 module.
- **`asn1_build_resultset`:** publisher output containing reconstructed ASN.1 semantic/runtime results.

The parser obtains ASN.1-specific lexical and grammar providers through `asn1_advisor`. The lexical analyzer's prepared state is cached in the parser object; parser engines and their tables remain part of `sdk/io/parser`.

### Parameterized notation boundary

The GLR grammar includes productions such as `ParameterizedAssignment`, `ParameterizedTypeAssignment`, `ParameterList`, `ParameterizedType`, `ActualParameterList`, and `ActualParameter`. Source examples include `FRAME{TypeParam, INTEGER:maxSize}` and `MyPacket ::= FRAME{ OCTET STRING, 1024 }`.

This establishes grammar coverage, not full parameterized-type semantics. Direct semantic construction/specialization probes exist, while the parser-to-publisher testcase path for parameterized instantiation remains disabled in the source snapshot. Do not infer end-to-end parameter binding and substitution from the productions alone.

## 3. Behavior Model

### Prepare and tokenize

The parser lazily prepares its lexical analyzer through `load()`. Preparation configures ASN.1 lexical behavior and loads ASN.1 token definitions from parser resources. `to_tokens()` scans the notation, converts lexical descriptions to `parser_token` values, skips comments, maps identifier-like values to the ASN.1 identifier token, and appends the generic EOF token.

### Parse tokens into a tree

`to_parsetree()` passes prepared tokens to the selected parser provider. The current source path obtains the ASN.1 GLR parser through the shared advisor/provider layer:

```text
asn1_advisor
    |
    v
get_glr_parser_asn1_by_import()
    |
    v
generic GLR parser
    |
    v
parse_tree
```

The parser engine remains in `sdk/io/parser`; `asn1_parser` supplies ASN.1-specific input and provider configuration.

### Reconstruct semantic results

```text
parse(notation, result)
    ├── parse(notation, parse_tree)
    │      ├── to_tokens()
    │      └── to_parsetree()
    └── to_result(parse_tree, result)
             |
             v
       asn1_publisher::build()
             |
             v
       asn1_build_resultset
```

`to_result()` gets the shared publisher from `asn1_advisor` and asks it to reconstruct semantic objects from the parse tree. It does not embed production handlers in the parser.

### Concrete caller path: notation to a published object

A caller that only needs the reconstructed result can use the `parse(notation, result)` overload. It performs the parse-tree stage and semantic publication internally:

```cpp
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>

asn1_parser parser(parser_type_t::glr, true);
asn1_build_resultset result;
return_t ret = parser.parse("Type1 ::= VisibleString", result);

if (errorcode_t::success == ret && result.object) {
    basic_stream output;
    result.object->publish(&output);
    // output now contains the reconstructed ASN.1 notation.
}
```

This is the convenience path for consumers interested in the published result. When debugging tokenization or grammar behavior, use the overload that returns a `parse_tree*` and inspect that tree before calling the publisher; otherwise those intermediate stages remain hidden behind the single call.

The same parse-tree-to-publisher boundary is exercised separately by `test/testcase/asn.1/runtime/testcase_publish.cpp`.

### Source-level test paths

- `test/testcase/asn.1/runtime/testcase_parser.cpp::test_asn1parser()` — notation through parser and parse-result assertions.
- `test/testcase/asn.1/runtime/testcase_publish.cpp` — staged parse-tree-to-semantic publishing.
- `test/testcase/asn.1/loader/testcase_loader.cpp` — separately inspects tokenization, parse-tree creation, and result publication.

These links describe source-level test paths; this documentation update did not execute the tests.
## 4. Relationships
- [Generic parser](../../parser/README.md) — lexer, parser engines, parse-tree model, and table resources.
- [ASN.1 publisher](asn1_publisher.md) — semantic reconstruction from the parse tree.
- [ASN.1 runtime](README.md) — module registry and runtime data model.
- [ASN.1 loader developer notes](../loader/asn1_loader.md) — file loading and staged parser use.
- `../basic/` — ASN.1 semantic and structural types.
- `../advisor/` — shared ASN.1 provider implementation.
