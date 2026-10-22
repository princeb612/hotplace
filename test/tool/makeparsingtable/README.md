## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: parser-table generation utility
```

# makeparsingtable

## 1. Role

`makeparsingtable` is a build-support executable that serializes a parser's generated tables into a `.ptb` file. It does not parse test input or run a testcase. Its output is consumed by the parser runtime and the parser/ASN.1 testcase build paths.

## 2. Model

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
```

The default parser type is LALR(1) in the command-line option structure, but the default accessor specifically returns the ASN.1 notation parser. The `-glr` option switches the selection to the ASN.1 parser built for GLR. The output file name is supplied independently with `-o`.

## 3. Important behavior and lifetime

The main routine initializes OpenSSL, parses options, creates logging according to the selected flags, and calls `generate_parsing_table()`. Generation checks `parser.ready()`; if the parser is not ready, it returns `not_ready`. Otherwise, `binary_parsing_table::learn()` obtains the parser's table representation and `write()` serializes it to the requested output path. The process then flushes logging, reports through the testcase result helper, and performs OpenSSL cleanup.

The generator does not choose its output path automatically. If `-o` is omitted, it exits the generation path without writing a table. Build automation supplies explicit output names.

## 4. Example from the source build

From the directory containing the built executable:

```sh
./makeparsingtable -o asn1notation.ptb
./makeparsingtable -o asn1.ptb -glr
```

- The first command uses the default parser selection and writes `asn1notation.ptb`.
- The second selects GLR and writes `asn1.ptb`.

In `CMakeLists.txt`, this post-build generation and packaging rule is enabled only when the compiler ID is GNU and the target platform is Windows. It runs both commands and then uses `zip parsingtable.zip asn1notation.ptb asn1.ptb`. The separate `etc/parsingtable/CMakeLists.txt` unpacks the stored archive into the configured testcase build directories; it does not invoke this generator.

## 5. Test and verification status

### 5.1 Source-level coverage

This executable prepares parser-table resources. Validation therefore includes generation exit status and artifact availability/consumability; ordinary parser behavior is exercised by downstream parser and ASN.1 testcase groups rather than by this tool alone.

### 5.2 Documentation and verification status

This description follows `sample.cpp` and the tool's CMake rule. The generator was not executed during this documentation update, so no new generation result is claimed.

## 6. Relationships

- [Parent tool directory](../README.md) — role of test-supporting tools in the test tree.
- [Parser runtime](../../../sdk/io/parser/README.md) — parser-table representation and import/execution.
- [Stored table archive](../../../etc/parsingtable/README.md) — artifact distribution and extraction.
- [Parser testcase group](../../testcase/io/parser/README.md) and [ASN.1 testcase group](../../testcase/asn.1/README.md) — consumers of the generated tables.
- `sample.cpp` — command-line parsing, parser selection, generation, and reporting.
- `CMakeLists.txt` — tool target and conditional post-build generation.

## 7. References

No external references are required for this build utility. The implementation and the related source-tree documents above define its behavior and integration.
