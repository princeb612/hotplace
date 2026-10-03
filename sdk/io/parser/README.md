# Parser

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1096
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```


`sdk/io/parser` is hotplace's grammar-driven parsing infrastructure. It provides lexical tokenization, CFG grammar representation, parsing-table generation, LALR/GLR execution, and parse-tree construction.

The subsystem is consumed directly by ASN.1 and can also be used independently for grammar experiments.

## Implementation map

```text
source text
    │
    ▼
lexical_analyzer
    │
    ▼
parser_token
    │
    ▼
cfg_grammar
    │
    ├── LALR(1) table generation
    └── GLR table generation
            │
            ▼
      binary_parsing_table
            │
            ▼
      parser execution
       ├── lalr1_parser
       └── glr_parser
            │
            ▼
      graph-structured
       stack (GSS)
            │
            ▼
        parse_tree
```

## Documents

- [Parser design and implementation notes](parser.md) — continuous study/development record
- [Parser lexer](parser-lexer.md)
- [Grammar and parsing-table generation](parser-generation.md)
- [LALR/GLR parser engines](parser-engines.md)
- [Parse tree](parser-tree.md)
- [LALR vs GLR](lalr-vs-glr.md)
- [Parsing-table binary format](parsing-table-binary-format.md)

## Related areas

- `../asn.1/` — primary higher-level consumer
- `../basic/` — common values/streams used by parser code
- `../../base/` — common containers, strings and utility infrastructure

## Related tests

- `test/testcase/io/parser/`
- `test/testcase/asn.1/testvector_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`

The long `parser.md` document is intentionally retained. It records parser theory, experiments, traces, and implementation history that would be lost by reducing it to a short reference.
