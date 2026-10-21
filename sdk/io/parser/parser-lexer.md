## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parser Lexer

## 1. Role

The lexical layer converts source text into `lexical_token` objects stored in a `lexical_context`.

```text
source text
    │
    ▼
lexical_analyzer
    │
    ▼
lexical_context
    │
    ▼
lexical_token[]
```

The parser itself consumes parser tokens; the lexer is responsible for recognizing source-level words/symbols and preserving their positions.

## 2. Data Model
### lexical_analyzer

`lexical_analyzer` manages the registered token vocabulary and performs tokenization.

Important operations include:

- `add_token()` — register a token string and token ID
- `prepare()` — prepare lookup structures
- `parse()` — tokenize raw memory, `std::string`, or `basic_stream`
- `lookup()` / `rlookup()` — map between token text and token ID
- `dump()` — inspect a lexical context

The analyzer also exposes configuration through `get_config()` and parser flags for tokenization behavior.

### lexical_token

A `lexical_token` is a lightweight reference to a region of the original source.

It records:

- token ID
- source position
- token length
- source line
- token index

It does not need to own a copy of the source text.

```text
source buffer
    │
    ├──────── token range ────────┐
    │                             │
    ▼                             ▼
"Type1 ::= INTEGER"        lexical_token
                           pos / size / line / type
```

`as_string()` can materialize the token text when needed.

### lexical_context

`lexical_context` owns the token sequence and retains the original source pointer/size.

It provides:

- indexed token lookup
- forward/reverse traversal
- source-position information
- token insertion hooks
- access to the last token

This makes the lexical result reusable by parser/test/debug code without repeatedly rescanning the input.

### Parser boundary

Higher-level parser code maps lexical tokens to grammar terminal symbols.

For ASN.1 this distinction is important:

```text
lexical token
   │
   │ token translation / mapping
   ▼
grammar terminal
   │
   ▼
LALR / GLR parser
```

The test documentation explicitly treats lexer-token registration, token precedence, and lexer-to-parser mapping as separate maintenance points.

## 3. Behavior Model
- A `lexical_token` stores an offset and length into the source rather than owning a copy of the lexeme. `lexical_context` retains the source pointer and size, so callers must keep the backing bytes valid while token text may be read.
- Token IDs are assigned by the lexer vocabulary. The grammar parser consumes terminal symbols from its own grammar; consumers must map lexer IDs/names to those terminals rather than assuming that a lexical token ID is already a parser state or production ID.
- `prepare()` establishes the built-in token vocabulary and lookup support. `add_token()` extends or overrides the vocabulary for the language being recognized; call `prepare()` and configure language-specific tokens in the order expected by the consumer.
- Configuration changes tokenization behavior. For example, `handle_lvalue_usertype` affects assignment-left-hand-side recognition, while `handle_hexstring` enables ASN.1-style quoted hex-string handling. Token counts and kinds can therefore change with configuration even for the same source text.
- A lexical context is a tokenization result, not a complete parse result. It preserves positions and token boundaries for later parsing and diagnostic output.

### Source-level evidence
`test/testcase/io/parser/testcase_lexer.cpp::test_lexer()` feeds a multi-line `PersonnelRecord` fragment to the lexer. The first pass uses the basic vocabulary and asserts 105 tokens. The second registers ASN.1 tokens, enables `handle_lvalue_usertype`, and registers `::=` and `--`, then asserts 93 tokens. The callback prints token type/name, line, index, offset, length, and source slice; these fields are useful when investigating why a lexical option changes token boundaries.

`test_lexer_hexstring()` enables `handle_hexstring`, registers `::=` and `IA5String`, and checks the exact token-ID sequence for `Pkt1Header ::= PACKET-HEADER{ '404B5431'H, IA5String }`. This is a stronger example than a token dump alone because the expected sequence is compared with the actual sequence.

## 4. Relationships
### Related document

- `parser-generation.md` — grammar symbols and parser table construction

### Implementation source navigation
- `lexical_analyzer.hpp`, `lexical_analyzer_parse.cpp`
- `lexical_token.cpp`, `lexical_context.cpp`
- `parser_resource.hpp`, `resource/ascii_tokens.cpp`, `resource/parser_tokens.cpp`
- `test/testcase/io/parser/testcase_lexer.cpp`
