## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1108
Source basis: Revision 1105
Documented with GPT-6
Scope: parser-table generation utility
```

# makeparsingtable

## 1. Role

`makeparsingtable` is a build-support executable that builds a parser's generated table representation and serializes it to a `.ptb` file. Its responsibility ends at resource generation; importing the table and parsing input belong to the parser runtime.

## 2. Tool Model

### Generation flow

```text
command-line options
  ├─ -o <file>  output table file (required)
  └─ -glr       select GLR parser
          │
          ▼
get_parser(type)
  ├─ default -> asn1_advisor::get_notation_parser_by_build()
  └─ GLR     -> asn1_advisor::get_parser_by_build()
          │
          ▼
parser.ready()
          │
          ▼
binary_parsing_table::learn(parser)
          │
          ▼
binary_parsing_table::write(output, parser)
          │
          ▼
       <file>.ptb
```

The command-line option structure defaults to the LALR(1) parser type, while the default accessor specifically returns the ASN.1 notation parser. The `-glr` option selects the ASN.1 parser built for GLR. The output path is supplied independently with `-o`; the generator does not choose a destination automatically.

The main routine initializes OpenSSL, parses options, configures logging according to the selected flags, and calls `generate_parsing_table()`. Generation checks `parser.ready()`; if the parser is not ready, it returns `not_ready`. Otherwise, `binary_parsing_table::learn()` obtains the parser's table representation and `write()` serializes it to the requested output path. The process then flushes logging, reports through the testcase result helper, and performs OpenSSL cleanup. If `-o` is omitted, no table is written.

### Build integration

The CMake post-build rule is enabled only when the compiler ID is GNU and the target platform is Windows. It runs both commands below, then packages the generated files as `parsingtable.zip`:

```sh
./makeparsingtable -o asn1notation.ptb
./makeparsingtable -o asn1.ptb -glr
zip parsingtable.zip asn1notation.ptb asn1.ptb
```

The first command uses the default parser selection; the second selects GLR. This generation-and-packaging step is separate from `etc/parsingtable/CMakeLists.txt`, which extracts the stored archive into the configured parser and ASN.1 testcase build directories. Extraction does not invoke `makeparsingtable`.

### Boundary to the parser runtime

```text
makeparsingtable
  parser CFG -> build -> binary parsing table
                              │
                              ▼
parser runtime
  import -> parser state -> parse input -> parse tree
```

The tool constructs the serialized table; the runtime imports the resource and uses it during parsing. Parser behavior and parse-tree construction are therefore not results demonstrated by table generation alone. This documentation update did not execute the generator, so it makes no new claim about a successful generation run.

## 3. Relationships

- [Parent tool directory](../README.md) — role of parser-table generation in the test-supporting build.
- [Parser runtime](../../../sdk/io/parser/README.md) — binary-table import and parsing behavior.
- [ASN.1 implementation](../../../sdk/io/asn.1/README.md) — parser consumer and grammar integration.
- [Stored table archive](../../../etc/parsingtable/README.md) — artifact distribution and extraction.
- [Parser testcase group](../../testcase/io/parser/README.md) and [ASN.1 testcase group](../../testcase/asn.1/README.md) — consumers of the generated tables.
- `sample.cpp` — command-line parsing, parser selection, generation, and reporting.
- `CMakeLists.txt` — executable target and conditional post-build generation.
