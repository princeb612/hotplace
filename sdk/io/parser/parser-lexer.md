# Parser Lexer

## Role

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

## lexical_analyzer

`lexical_analyzer` manages the registered token vocabulary and performs tokenization.

Important operations include:

- `add_token()` — register a token string and token ID
- `prepare()` — prepare lookup structures
- `parse()` — tokenize raw memory, `std::string`, or `basic_stream`
- `lookup()` / `rlookup()` — map between token text and token ID
- `dump()` — inspect a lexical context

The analyzer also exposes configuration through `get_config()` and parser flags for tokenization behavior.

## lexical_token

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

## lexical_context

`lexical_context` owns the token sequence and retains the original source pointer/size.

It provides:

- indexed token lookup
- forward/reverse traversal
- source-position information
- token insertion hooks
- access to the last token

This makes the lexical result reusable by parser/test/debug code without repeatedly rescanning the input.

## Parser boundary

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

## Related tests

- `test/testcase/io/parser/testcase_lexer.cpp`
- `test/testcase/io/parser/testcase_parser.cpp`
- `test/testcase/io/parser/testvector_parser.cpp`

## Related source

- `lexical_analyzer.*`
- `lexical_token.*`
- `lexical_context.cpp`
- `types.hpp`

## Related document

- `parser-generation.md` — grammar symbols and parser table construction
