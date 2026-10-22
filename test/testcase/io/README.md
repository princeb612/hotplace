## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# I/O testcase suite

## 1. What

The `io` testcase target covers several distinct implementation layers: OID lookup and ASN.1 OID conversion; named-field binary payload construction and parsing; QUIC variable-length integers; file-backed streams; URL component splitting; lexical analysis; grammar parsing and parser-table import; ASN.1 module-boundary detection; and optional operating-system exercises.

These are not one homogeneous test suite. The default run covers the basic, stream, string, lexer, parser, and YAML-vector functions. The MLFQ producer/consumer scenario and Linux process-event netlink monitor are opt-in and have different execution constraints.

## 2. How

### 2.1 Entry point and invocation order

1. `sample.cpp::main()` creates the command-line parser and test logger.
2. It invokes the default groups in source order: `testcase_oid()`, `testcase_payload()`, `testcase_payload_quic()`, `testcase_filestream()`, `testcase_string()`, `testcase_lexer()`, `testcase_parser()`, and `testcase_testvector_parser()`.
3. The OID group checks dictionary initialization, dotted-decimal lookup, and ASN.1 textual OID conversion followed by lookup.
4. The payload groups exercise serialization/parsing, field-length references, conditional groups, 24-/48-bit fields, a DTLS record header, a 256-bit bignumber round trip, and QUIC variable-integer cases.
5. The filestream and string groups exercise file sizing/mapping/writes/seek/read-back and four HTTPS URL examples with field-level assertions.
6. The lexer and parser groups check token counts/classifications/sequences, reducer behavior, parser-table import, ASN.1 notation through parser variants, and parameterized notation.
7. `testcase_mlfq()` runs only with `-mlfq`; `testcase_netlink()` runs only with `-netlink` and waits for SIGINT. A default run does not establish that either optional path executed.

### 2.2 Test target, fixture staging, and parser data flow

1. The directory's `CMakeLists.txt` collects `*.cpp`, `basic/*.cpp`, `parser/*.cpp`, `stream/*.cpp`, `string/*.cpp`, and `system/*.cpp` into the `io` target.
2. It collects top-level YAML files and `parser/*.yml`, then copies those fixtures into the build tree's testcase `io` directory. These functions are dispatched by one executable; each source file is not a separate CTest target.
3. For the parser vectors, load `testvector_parser.yml` using schema `PARSER` and read `item`, `asn1`, `expect`, `level_trigger`, and `edge_trigger`.
4. Run the Aho-Corasick reducer over the ASN.1 source, map rule IDs to clause names, and compare the actual clause ranges and both trigger-range maps with their expected maps.
5. Keep parser-table import separate from the YAML-vector path: `test_load_parsingtable()` loads `asn1notation.ptb`, parses a minimal notation, and checks parser readiness/result. Changes to parser-table generation or CMake copying can affect this path independently.

#### PARSER YAML schema

The `PARSER` vectors in `parser/testvector_parser.yml` describe ASN.1 source text, expected clause ranges, and expected level-/edge-trigger reducer ranges. The actual consumer reads `expect`, `level_trigger`, and `edge_trigger` as three separate maps.

````yaml
testvector:
  - example: string                 # [mandatory] testcase
    schema: PARSER                  # [mandatory] "PARSER"
    items:
      - item: string                # [mandatory]
        asn1: |
          statements                # [mandatory] ASN.1 notation
        expect:                     # [mandatory] clause names -> range arrays
          imports_clause: [[begin, end], ...]
          exports_clause: [[begin, end], ...]
          header_clause: [[begin, end], ...]
          end_module: [[begin, end], ...]
        level_trigger:               # [mandatory] reducer range expectations
          unmatched: [[begin, end], ...]
          matched: [[begin, end], ...]
        edge_trigger:                # [mandatory] reducer range expectations
          unmatched: [[begin, end], ...]
          matched: [[begin, end], ...]
````

The source compares the expected clause map and both trigger maps with the ranges produced by the reducer. This schema sketch reflects the current fixture structure; it is not a substitute for the detailed comparison path above.

### 2.3 Assertion strength

1. Treat full byte-vector equality and exact expected token sequences as output-specific checks.
2. Treat status-only checks as evidence of the returned status, not of every parsed field or internal state.
3. In MLFQ, the producer/consumer work is coordinated through threads and semaphores, but the printed priority summary is not compared with a complete expected schedule.
4. Treat netlink output as event-monitor diagnostics rather than a short deterministic expected-output test.
5. For subsystem-specific detail, follow the corresponding child document's input, operation sequence, asserted result, and untested boundary.
## 3. Evidence

### Source-level coverage

**1. OID lookup and conversion**

```text
OID text / encoded form -> parse or convert -> dictionary lookup
  -> compare selected dotted-decimal/name results
```

**2. Payload and QUIC varint**

```text
payload schema + values -> serialize -> compare complete expected byte buffer
fixed/referenced-length input -> parse -> compare decoded fields/length/padding
  -> serialize again -> compare bytes only where the case asserts it

QUIC integer -> encode -> compare known-answer bytes
  -> decode -> compare value/consumed length for selected cases
```

These are selected vectors, not exhaustive malformed-input or all-boundary tests.

**3. File stream and URL split**

```text
file -> truncate/size -> mmap/write -> unmap -> seek/read
  -> compare first native-endian integer == 0x12345678
  -> remaining written values are not compared

URL -> split_url() -> assert scheme/host/port/URI/path/query/fragment
URI -> to_keyvalue() -> printed output only; no expected-map comparison
```

**4. Lexer, parser and YAML reducer**

```text
lexer input -> tokenize -> compare count/first type or exact type vector
parser input/table -> parse -> check status/readiness or selected parse result
YAML module-boundary vectors -> reducer ranges + rule IDs -> clause names
  -> compare expected multimap == actual multimap
```

Status/readiness checks do not prove complete parse-tree shape.

**5. Optional system paths**

```text
-mlfq   -> producer/consumer scenario -> check selected scenario status
        -> priority summary printed, not compared with expected schedule
-netlink -> Linux/glibc process-event monitor -> wait for SIGINT -> print events
         -> no deterministic expected event sequence
```

The default dispatcher does not invoke these paths without the options. The aggregate report alone does not prove either path ran.



The common [Test Report Snapshot](../test-report-status.md) records the last supplied aggregate report as **Revision 1104 · MinGW64/GCC · CTest**, associated with 596 pass, 0 expt, 0 fail, 0 skip, and 0 triv for the entire `io` group. This is a parent-target report; it does not provide separate outcome totals for the child directories and does not prove that the optional Linux netlink path ran.

The report's run association comes from the maintainer-supplied context; the report files do not independently identify the tested commit, exact GCC version, or full build flags. The source/documentation basis here is Revision 1105, documented as Revision 1106. This documentation change did not execute tests.

Revision 1106 CTest counts from other groups/environments must not be substituted for this Revision 1104 testcase-level report: they count CTest test files/targets rather than individual categorized testcase outcomes.



## 4. Relationships

- [`sdk/io/README.md`](../../../sdk/io/README.md) — implementation-side I/O module map.
- [`CMakeLists.txt`](CMakeLists.txt) — source and YAML collection/copy behavior.
- [`sample.cpp`](sample.cpp) — command-line options and explicit dispatch order.
- [Basic testcases](basic/README.md) — OID, payload, QUIC varint, and integer representation.
- [Parser testcases](parser/README.md) — lexer, grammar parser, parser-table import, and YAML reducer.
- [Stream testcases](stream/README.md) — mapped file and stream read-back.
- [String testcases](string/README.md) — URL component splitting.
- [System testcases](system/README.md) — opt-in MLFQ and netlink paths.
- [Test Report Snapshot](../test-report-status.md) — shared runtime evidence and provenance.

## 5. References

- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000) — Appendix A provides the known-answer basis for the QUIC variable-length integer cases.
- [RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986) — URI syntax background for the selected URL splitting examples.

