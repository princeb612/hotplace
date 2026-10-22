## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# Parser testcases

## 1. What

The parser testcase area exercises four related but distinct layers:

- lexical tokenization, including comment handling, user-defined type recognition, and ASN.1 hex-string tokens;
- parser-table construction/import and syntax parsing for ASN.1 notation;
- parameterized assignments and information-object-class syntax through the GLR parser;
- a token-pattern reducer that identifies ASN.1 module headers, EXPORTS/IMPORTS clauses, and END markers before full grammar parsing.

The reducer tests are not substitutes for grammar parsing. They detect token ranges and parser-switching boundaries; the parser tests pass token streams to LALR/GLR parser instances.

## 2. How

### 2.1 tokenization option matrix

1. **Entry:** `testcase_lexer() → test_lexer_options()` in `testcase_lexer.cpp`.

2. The test iterates ten rows containing ASN.1 notation, expected token count, expected first token type, `handle_comments`, and `handle_lvalue_usertype` settings. Before each row, `prepare_lexer_asn1()` resets and prepares the lexer, and the requested flags are applied. The lexer parses the input into a shared `lexical_context`; the test traverses that context and counts emitted tokens while recording the first token type.

3. The rows vary comment handling for `-- empty SEQUENCE` and `-- SEQUENCE`, distinguish assignment-left-hand-side tokens from usertype tokens, reuse names such as `Name`/ `Type`, and include application-tagged and integer-constraint forms. Each row records parse status, asserts the expected token count, and asserts the first token classification. The shared lexical context and repeated lexer preparation are relevant to this test's purpose: it checks how options affect tokenization and reuse of usertype knowledge, not just one isolated input.

4. The exact expected counts are encoded in the source table (including 12 versus 8/6 tokens for comment-related examples and 3 tokens for `Name ::= VisibleString`). These assertions do not compare every token's type/value sequence; only the count and first type are explicit oracles for this matrix.

### 2.2 two tokenization configurations on an ASN.1 sample

1. **Entry:** `test_lexer()`.

2. The input is a multi-assignment `PersonnelRecord` ASN.1 sample containing application tags, SET/SEQUENCE fields, user-defined names, DEFAULT, and a trailing `-- YYYYMMDD` comment. The first pass uses `lexer.prepare()` and asserts that 105 token descriptions are produced. The second pass calls `prepare_lexer_asn1()`, enables `handle_lvalue_usertype`, registers `::=` and `--` tokens, reparses the same sample, and asserts 93 tokens.

3. This is a comparison of token counts across configurations. It does not compare all 105/93 token descriptions against a golden token stream, and it does not assert that the parser accepts the sample as a grammar.

### 2.3 exact token-type sequence

1. **Entry:** `test_lexer_hexstring()`.

2. The lexer is prepared with `handle_hexstring = 1`, and the tokens `::=` and `IA5String` are registered. The input is:

```text
Pkt1Header ::= PACKET-HEADER{ '404B5431'H, IA5String }
```

3. The testcase collects every emitted token type and compares the full vector with:

```text
token_lvalue, token_assign, token_id, token_lbrace,
token_hexstring, token_comma, token_ia5string, token_rbrace
```

4. Unlike the previous lexer cases, this checks the entire token-type sequence. It does not separately compare each token's source spelling, position, or length.

### 2.4 Aho–Corasick reducer over ASN.1 examples

1. **Entry:** `testcase_parser() → test_ac_reducer()`.

2. The reducer is configured by `prepare_asn1module_reducer()`, which defines virtual patterns for module-header boundaries, EXPORTS/IMPORTS starts and ends, and END. The testcase iterates `example1.asn1` through `example13.asn1`, opens each with `file_stream`, memory-maps it, and calls `ac_search_and_printall()`.

3. The helper lexes the input, normalizes left-value tokens to identifiers, omits comment tokens, searches the resulting token stream, and prints matched ranges. The final result is recorded with `_test_case.test(ret, ...)`. There is no fixed expected range list for these thirteen files in this function; its pass condition is the reducer helper's return status, not a comparison against golden ranges. The files therefore act as broad diagnostic samples rather than individually asserted range oracles.

### 2.5 import generated LALR table and parse a minimal assignment

1. **Entry:** `test_load_parsingtable()`.

2. The testcase reads `asn1notation.ptb` into a `lalr1_parser` using `binary_parsing_table::read()` and records that return status. It then passes `Type1 ::= VisibleString` to `test_asn1parser()`. The helper tokenizes the input, normalizes left-value tokens, omits comments, appends an EOF token, calls `parser.parse()`, prints the parse tree, and records the parse return status.

3. This exercises the import artifact and a minimal assignment. The source does not compare the imported table's bytes or a golden parse-tree structure. The test depends on the generated table being available in the testcase working directory; CMake copies data files, while parser-table generation/copying is handled by the repository's parsing-table build flow.

### 2.6 shared syntax cases through four parser instances

1. **Entry:** `test_asn1_notation()`.

2. The test obtains four parser instances from `asn1_advisor`:

1. LALR(1) parser whose table is built at runtime;
2. LALR(1) parser whose table is imported;
3. GLR parser whose table is built at runtime;
4. GLR parser whose table is imported.

3. Each parser's `ready()` state is asserted before the vector loop. The shared table contains assignment examples, tagged and nested types, SEQUENCE/SET/CHOICE, primitive types, enumerations, DEFAULT/OPTIONAL fields, constraints (single values, ranges, unions, intersections, EXCEPT, SIZE, FROM, PATTERN, MIN/MAX), and non-assignment fragments. The same notation string is passed as both display text and parser input for every row, and the same table is processed by all four parser instances.

4. The helper records whether parsing succeeds and emits parse-tree diagnostics. It does not compare the resulting tree against a golden tree or assert semantic equivalence among all four trees. Therefore this vector table is primarily a syntax acceptance regression set across table-construction/import paths, not a semantic ASN.1 compiler conformance suite.

### 2.7 parameterized assignments and information-object classes

1. **Entry:** `test_asn1_parameterized()`.

2. The vector table contains parameterized type assignments such as `Envelope {TypeParam}`, `KeyValuePair {KeyType, ValueType}`, and `BoundedArray {ElementType, INTEGER : MaxSize}`; references that instantiate those templates; nested parameterized references; and information-object-class forms using `CLASS`, `WITH SYNTAX`, and field references such as `&Type` and `&id`.

3. The table's flags mark each case as parameterized and/or information-object-class syntax. The current invocation calls `lambda_test(item_asn1ioc, p)` on the built GLR parser, so cases carrying the IOC bit are selected; parameterized rows are also marked with that bit in the source table. The parser readiness is asserted, then each selected notation is passed to the same parse-status helper. As with the notation table, no golden parse-tree or semantic-resolution result is compared.

### 2.8 data-driven module clause ranges and parser switching

1. **Entry:** `testcase_testvector_parser() → test_yaml_testvector_parser()`. The vectors are in `testvector_parser.yml` under schema `PARSER`.

2. For each YAML item, the testcase reads `item` and the ASN.1 source string, then converts the `expect`, `level_trigger`, and `edge_trigger` maps into multimaps of names and ranges. It lexes the ASN.1 text, normalizes left-value tokens, discards comments, and runs the Aho–Corasick reducer. Reducer rule IDs are mapped to `end_module`, `header_clause`, `exports_clause`, and `imports_clause`. It then compares the complete expected clause-range multimap with the formatted results.

3. The YAML includes seven named cases: a simple module, an OID header with EXPORTS/IMPORTS, EXPORTS ALL, a parameterized module with an unmatched body region, a larger purchase-order module, a two-module example with parameterized definitions/imports, and a pair of modules exercising IMPORTS/EXPORTS. Each case also specifies expected level-trigger and edge-trigger ranges. `travel_ranges(trigger_t::level, ...)` and `travel_ranges(trigger_t::edge, ...)` produce `matched`/`unmatched` ranges, which are compared to their respective YAML expectations.

4. This is the most explicit range oracle in the parser area: it checks expected boundaries and trigger classification, not merely successful execution. The rule IDs used for clause names are source-coupled to `prepare_asn1module_reducer()`; if the reducer patterns/order change, update and review the mapping and YAML expectations together. Range vectors do not prove full grammar validity or parser error recovery.

## 3. Evidence

### Source-level coverage

**1. Lexer option matrix**

```text
configured lexer input -> tokenize -> compare token count + first token type
hex-string input -> tokenize -> compare complete token-type vector
```

The option matrix does not compare the full token vector for every row.

**2. Parser/reducer and parser table**

```text
grammar sample / imported table -> parse -> check selected return status
table import -> check parser readiness / selected parse result
```

These checks do not establish every grammar branch or the complete parse-tree shape.

**3. YAML module-boundary vectors**

```text
testvector_parser.yml
  -> load PARSER schema and selected fields
  -> Aho-Corasick reducer returns ranges + rule IDs
  -> map rule IDs to clause names
  -> construct actual range multimap
  -> compare actual multimap == expected multimap
```

**4. Optional parser variants**

```text
dispatcher invokes variant + generated/imported table available
  -> parser path executes
otherwise -> source inclusion alone does not establish runtime coverage
```

Parameterized/GLR and generated-table paths must be tied to their actual dispatch and table availability.



The shared [Test Report Snapshot](../../test-report-status.md) records the aggregate `io` report only; it has no separate parser, lexer, or reducer totals. The associated run context is Revision 1104 · MinGW64/GCC · CTest, but the report files do not independently identify the tested commit or full build configuration. This documentation update did not rebuild or execute the suite.

Source-level evidence varies by TC: token-count/first-token assertions for the lexer option matrix; exact token-type vector equality for the hex-string case; return-status checks for file reducer/parser examples; readiness checks for parser tables; and full expected range-map comparisons for the YAML module-boundary vectors. Do not describe all of these as equivalent-strength assertions.



## 4. Relationships

- `sdk/io/parser/` — lexical analyzer and parser implementation.
- `sdk/io/asn.1/` — higher-level ASN.1 consumers.
- [I/O testcase suite](../README.md) — dispatch and aggregate report context.
- [`CMakeLists.txt`](../CMakeLists.txt) and [`sample.hpp`](../sample.hpp) — source collection, declarations, and shared harness.
- [`testcase_lexer.cpp`](testcase_lexer.cpp) — lexer option matrix, structural sample, and hex-string sequence.
- [`testcase_parser.cpp`](testcase_parser.cpp) — reducer file samples, parser-table import, notation and parameterized vectors.
- [`testvector_parser.cpp`](testvector_parser.cpp) and [`testvector_parser.yml`](testvector_parser.yml) — expected module ranges and trigger behavior.
- [`asn1module.cpp`](asn1module.cpp) and [`asn1module.hpp`](asn1module.hpp) — shared lexer setup, reducer patterns, and parser helper.
- `test/tool/makeparsingtable`, `etc/parsingtable/`, and root CMake copy rules — generation and build-tree availability of `asn1notation.ptb`.

## 5. References

- [RFC 6025 — ASN.1 Translation](https://www.rfc-editor.org/rfc/rfc6025) — background on ASN.1 notation and translation considerations; this testcase suite is not a complete conformance implementation.
- [OSS Nokalva — ASN.1 Made Simple examples](https://www.oss.com/asn1/resources/asn1-made-simple/example.html) — source comment in the purchase-order vector identifies this ASN.1 example as input background.
