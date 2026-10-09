# ASN.1 Parser

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1102
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

`asn1_parser` is the hotplace ASN.1 notation entry point that bridges the lexical analyzer, the parser tables, the parse tree, and semantic publication. It is a lightweight runtime-facing wrapper around the existing lexer/parser infrastructure.

## Role in hotplace

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

## Main operations

### `parse()`

The convenience overloads perform the complete pipeline.

```text
parse(notation, result)
    -> parse(notation, parse_tree)
    -> to_result(parse_tree, result)
```

The parse-tree overload stops after syntax parsing:

```text
parse(notation, parse_tree)
    -> to_tokens()
    -> to_parsetree()
```

### `to_tokens()`

`to_tokens()` invokes the hotplace `lexical_analyzer`, converts lexical descriptions into the parser's `parser_token` representation, skips comments, maps lexical l-values to the ASN.1 identifier token, and appends the parser EOF token.

The lexer is configured for the ASN.1 grammar, including quoted values, comments, l-value/usertype handling, and ASN.1 parameterized syntax.

### `to_parsetree()`

`to_parsetree()` passes the prepared token vector to the selected parser implementation. The current source obtains the parser provider from `asn1_advisor`. The selected runtime path uses the imported GLR parser:

```text
get_parser()
    -> get_glr_parser_asn1_by_import()
```

The parser itself remains part of `sdk/io/parser`; `asn1_parser` only provides the ASN.1-specific runtime-facing adapter.

### `to_result()`

`to_result()` obtains the prepared shared publisher from `asn1_advisor` and asks it to build semantic results from the parse tree.

```text
parse_tree
    |
    v
asn1_advisor::get_instance()->get_publisher()
    |
    v
asn1_publisher::build()
    |
    v
asn1_build_resultset
```

This makes `asn1_parser` the visible boundary between syntax parsing and semantic construction without embedding the publisher's grammar handlers in the parser itself.

## Grammar work: parameterized notation

The current ASN.1 GLR grammar includes productions for parameterized assignments and invocations. The grammar describes these forms through `ParameterizedAssignment`, `ParameterizedTypeAssignment`, `ParameterizedValueAssignment`, `ParameterList`, `ParameterizedType`, `ActualParameterList`, and `ActualParameter`. Actual parameters include type/value forms and brace-delimited forms.

This is a grammar-capability statement, not a claim that parameterized ASN.1 is fully implemented end to end. In the current working tree, the parameterized testcase contains a `FRAME{TypeParam, INTEGER:maxSize}` example and a `MyPacket ::= FRAME{ OCTET STRING, 1024 }` instantiation, but the test entry point does not currently execute the parse/publish test path. Semantic binding, parameter substitution, and reliable instantiated-type construction should therefore remain documented as work in progress until the corresponding implementation and tests are enabled.

The current focus is to strengthen parsing of complex template/parameter syntax before proceeding with the semantic prototype.

## Preparation and parser resources

The parser lazily prepares its lexical analyzer through `load()`.

The preparation step:

- configures the lexical analyzer for ASN.1 handling;
- loads ASN.1 token definitions from `parser_resource`;
- keeps the prepared state in `_ready`.

The parser therefore uses repository-provided parser resources rather than constructing a complete grammar table dynamically for every parse operation.

## Related source

- `sdk/io/asn.1/runtime/asn1_parser.hpp`
- `sdk/io/asn.1/runtime/asn1_parser.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher.*`
- `sdk/io/asn.1/asn1_advisor.hpp`
- `sdk/io/parser/lexical_analyzer.*`
- `sdk/io/parser/lalr1_parser.*`
- `sdk/io/parser/parse_tree.*`

## Related tests

- `test/testcase/asn.1/testcase_basic3.cpp`
- `test/testcase/asn.1/loader/testcase_loader.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`

The loader testcase is particularly useful because it explicitly exercises `to_tokens()`, `to_parsetree()`, and `to_result()` as separate stages.
