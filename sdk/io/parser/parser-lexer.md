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

### Practical example: tokenize a small ASN.1 assignment

Consider `Name ::= VisibleString`. The lexer can recognize the assignment's name, assignment operator, and type token before any grammar rule decides whether that sequence is valid:

```cpp
lexical_analyzer lexer;
lexical_context context;
prepare_lexer_asn1(lexer);
lexer.get_config().set("handle_comments", 1).set("handle_lvalue_usertype", 1);
lexer.add_token("::=", token_assign);

const char* source = "Name ::= VisibleString";
lexer.parse(context, source, strlen(source));
```

The matching testcase expects three tokens for this configuration. The important result is not merely the count: each token retains a source span, so a diagnostic can identify the original spelling and location without copying every lexeme. Lexer token IDs still need to be mapped to the grammar's terminal symbols by the consumer.

## 2. Data Model

### lexical_analyzer: vocabulary and configuration

The analyzer holds the registered token vocabulary and lookup structures prepared from it. The vocabulary maps token spelling to lexer token IDs and supports reverse lookup. Configuration flags alter how the same source bytes are segmented; they are part of the lexical input contract, not grammar productions.

- add_token() registers a token spelling and ID.
- prepare() prepares built-in vocabulary and lookup support.
- lookup() / rlookup() convert between token spelling and lexer ID.
- get_config() exposes lexical options.
- parse() accepts source memory, std::string or basic_stream input.

### lexical_token: a source span

A token stores its lexical ID and coordinates into the original source.

| Field | Meaning |
|---|---|
| Token ID | Vocabulary entry recognized by the lexer |
| Position / length | Byte range of the lexeme in the source |
| Line | Source line associated with the token |
| Token index | Position in the lexical sequence |

The token need not own a copy of the lexeme. as_string() materializes text from the source span when required.

### lexical_context: token sequence and source anchor

The context owns the token objects in sequence and retains the source pointer and size used by those spans. It supports indexed lookup, forward/reverse traversal, insertion hooks, last-token access and source-position inspection.

```text
source buffer (caller-owned lifetime)
       ▲
       │ token position + length
       │
lexical_context
  ├─ source pointer / size
  └─ ordered lexical_token objects
       ├─ lexer ID
       ├─ source offset / length
       ├─ line
       └─ token index
```

The token sequence can outlive the immediate scan operation, but token text remains valid only while the referenced source storage remains valid.

### Separate token namespaces

A lexer token ID identifies a recognized source token. A grammar terminal identifies a symbol in a production/table. The consumer's mapping between them must be maintained explicitly; the IDs are not interchangeable.

## 3. Behavior Model

### Source scan to token sequence

```text
lexical_analyzer::parse(source, size, context)
          │
          ▼
apply prepared vocabulary + lexical configuration
          │
          ▼
scan source and recognize token spans
          ├─ token spelling/kind ─► lexer token ID
          ├─ source cursor ────────► position + length
          ├─ line tracking ────────► line
          └─ emission order ───────► token index
                                         │
                                         ▼
                              lexical_context token sequence
                                         │
                                         ▼
                              consumer maps tokens to grammar
```

### Vocabulary preparation and language-specific options

1. Prepare the built-in vocabulary and lookup structures.
2. Register or override language-specific tokens required by the consumer.
3. Set lexical configuration before scanning.
4. Parse the source with that vocabulary/configuration.
5. Inspect token IDs and source spans when verifying tokenization behavior.

Options can change both token kind and token boundaries. In ASN.1-oriented tests, handle_lvalue_usertype affects assignment-left-hand-side recognition and handle_hexstring enables quoted hexadecimal-string handling. Token counts therefore describe a particular configuration, not an invariant of the source text.

### Failure and verification boundary

A lexical context represents tokenization, not grammar acceptance. The next stage can still reject the token sequence because its terminal mapping or grammar differs. Lexer tests should separately assert token IDs, positions/lengths and configuration-sensitive token counts.

### Source-level evidence

test/testcase/io/parser/testcase_lexer.cpp::test_lexer() feeds a multi-line PersonnelRecord fragment to the lexer. The basic pass asserts 105 tokens; the ASN.1-configured pass registers ::= and --, enables handle_lvalue_usertype, and asserts 93 tokens. test_lexer_hexstring() enables handle_hexstring and compares the actual token-ID sequence for Pkt1Header ::= PACKET-HEADER{ '404B5431'H, IA5String } against an expected sequence.

## 4. Relationships
### Related document

- `parser-generation.md` — grammar symbols and parser table construction

### Implementation source navigation
- `lexical_analyzer.hpp`, `lexical_analyzer_parse.cpp`
- `lexical_token.cpp`, `lexical_context.cpp`
- `parser_resource.hpp`, `resource/ascii_tokens.cpp`, `resource/parser_tokens.cpp`
- `test/testcase/io/parser/testcase_lexer.cpp`
