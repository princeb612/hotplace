## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase procedure, vectors & evidence     │
└──────────────────────────────────────────────┘
```

# CBOR testcase suite

## 1. What

This directory verifies the CBOR implementation in `sdk/io/cbor/` through two complementary source-level paths:

- `testcase_rfc7049.cpp` builds CBOR values and object trees directly, then compares their encoded bytes or published concise representation with fixed hexadecimal expectations.
- `testvector_cbor.cpp` loads `testvector_cbor.yml`, parses each eligible encoded vector, and checks the resulting bytes or diagnostic representation.
- `sample.cpp` supplies the executable entry point, command-line options, test report output, and an optional one-off decode/diagnostic display. The sample path is not a separate assertion suite.
- `testvector_cbor.yml` stores named vectors as an example/schema plus items containing the input description, CBOR hex, diagnostic text, and optional `loss` metadata.

The vectors include RFC 7049 examples and retained COSE-related examples in the YAML asset. They are known-answer inputs for the exercised cases, not a claim of exhaustive CBOR conformance.

## 2. How

### 2.1 Test entry and execution order

1. `sample.cpp::main()` configures command-line options and logging.
2. It calls `testcase_rfc7049()`, then `testcase_testvector_cbor()`, flushes the logger, and emits the test report.
3. `testcase_rfc7049()` dispatches `test_rfc7049_table4_1()` followed by `test_rfc7049_table4_2()`.
4. If `-e` is supplied, `whatsthis()` decodes the given hex bytes, parses them with `cbor_reader`, publishes a diagnostic expression, and dumps the original bytes. This is a manual inspection path, not an additional fixed-vector assertion.

### 2.2 RFC scalar, text, byte-string, and tag vectors

1. `test_rfc7049_table4_1()` selects helper routines such as `do_test_cbor_uint()`, `do_test_cbor_int()`, `do_test_cbor_float()`, `do_test_cbor_simple()`, and tagged-value helpers.
2. For `variant`-based values, `do_encode_test()` calls `cbor_encode`, converts the result to Base16, and compares the complete encoded string with the expected value.
3. For object-model cases, `do_cbor_test()` publishes diagnostic and binary/concise forms, then compares the concise hex representation with the expected bytes.
4. The table covers integer-width boundaries, negative integers and bignums, half/single/double floating-point values (including signed zero, subnormals, infinities and NaN bit patterns), Boolean/simple values, byte/text strings, UTF-8, and selected date/time, base16, encoded-data, and URI tags.
5. Interpret these as exact-output checks for the listed examples, not as exhaustive numeric conversion tests or an independent cross-implementation interoperability test.

### 2.3 Arrays, maps, indefinite-length items, and large integers

1. `test_rfc7049_table4_2()` constructs object trees with `cbor_array`, `cbor_map`, `cbor_pair`, `cbor_bstrings`, and `cbor_tstrings`.
2. Pass each tree to `do_cbor_test()`, which publishes the concise/binary representation and compares it with a literal expected hex string.
3. The selected examples include empty/populated and nested arrays/maps, 25-element arrays, indefinite-length arrays/maps, chunked byte/text strings, and nested definite/indefinite combinations.
4. The final cases serialize arrays of `bignumber` values at and beyond 64-bit limits, including signed 128-bit boundaries and the maximum unsigned 128-bit value. The assertions cover those supplied inputs, not every arbitrary-precision integer.

### 2.4 YAML-driven parse and publish checks

1. `test_yaml_testvector_cbor()` registers the `RFC 7049` callback and loads `testvector_cbor.yml`.
2. For each item, read `item`, `cbor`, and `diag`; if `loss` is present, skip that item in this callback.
3. Pass each eligible item to `do_parse_cbor_routine()`, open a `cbor_reader` context, and parse the encoded input.
4. On successful parse, publish the decoded object to diagnostic text and binary bytes.
5. Compare the published bytes with the decoded input hex. If that comparison fails, compare the diagnostic text with the expected diagnostic expression instead.
6. Record the result with `_test_case.assert(...)`. The success condition is bytes round-trip **or** diagnostic-text equality, not two independently required assertions. A `loss` vector is skipped and must not be counted as verified by this callback.

#### RFC 7049 YAML schema

`testvector_cbor.yml` uses the `RFC 7049` schema. `cbor` is the encoded input, `diag` is its expected diagnostic expression, and `loss` marks vectors skipped by this callback.

````yaml
testvector:
  - example: string          # [mandatory] testcase
    schema: RFC 7049         # [mandatory] "RFC 7049"
    items:
      - item: string         # [mandatory] diagnostic/description
        cbor: hexstring      # [mandatory]
        diag: |
          string             # [mandatory] diagnostic expression
        loss: boolean        # data-loss encoding; skipped by this callback
````

The schema is a field guide, not a statement that every listed item is checked. In particular, `loss` vectors are present in the asset but are not verified by this path.

### 2.5 Sample decode path

1. `whatsthis()` accepts hex content and decodes it to bytes.
2. It invokes `cbor_reader::parse()`, publishes a diagnostic expression, and dumps the original bytes.
3. Treat this output as a manual inspection aid; it is not compared with a fixed expected value and does not add conformance evidence.
## 3. Evidence

### Source-level coverage

The CBOR suite has two separate verification families. The fixed vectors in `testcase_rfc7049.cpp` construct values and compare encoded bytes; `testvector_cbor.cpp` starts from YAML-encoded bytes and tests reader/publisher behavior. Their oracles differ.

**1. Fixed scalar vectors — `do_encode_test()`**

```text
C++ value / variant
  -> cbor_encode::encode()
  -> Base16 encode output bytes
  -> compare output hex == expected hex
  -> _test_case.test(success | mismatch)
```

The helper compares the direct encoder's bytes with the literal vector. For helper cases that call `do_encode_test()`, this is a known-answer byte comparison.

**2. Object-model publisher vectors — `do_cbor_test()`**

```text
construct cbor_object tree
  -> cbor_publisher.publish(root, diagnostic)
  -> cbor_publisher.publish(root, binary)
  -> Base16 encode binary output
  -> compare concise hex == expected hex
  -> _test_case.test(success | mismatch)

diagnostic string
  -> logger output only
  -> not compared with an expected diagnostic string
```

This is the path used for arrays/maps, tags, indefinite-length objects, chunked strings and large-integer object trees. The expected hex is compared case-insensitively. The diagnostic expression is emitted for inspection, not independently asserted. Note that the scalar helper functions do not all traverse both paths: for example, `do_test_cbor_bool()` uses the direct encoder helper, while `do_test_cbor_simple()` uses the publisher helper.

**3. YAML vector path — `testvector_cbor.cpp`**

```text
testvector_cbor.yml
  -> load schema "RFC 7049"
  -> read item / cbor / diag / optional loss
  -> loss present?
       yes -> skip this callback's verification
       no  -> do_parse_cbor_routine(item, cbor, diag)
                -> cbor_reader.open()
                -> cbor_reader.parse(input hex)
                -> parse success?
                     no  -> test remains false
                     yes -> publish diagnostic + binary
                          -> compare published binary == decoded input bytes
                               equal -> pass candidate
                               unequal -> compare diagnostic == expected diag
                          -> _test_case.assert(test)
```

The YAML helper's actual oracle is **binary round-trip equality OR diagnostic-text equality**. It is not two mandatory assertions: a diagnostic match can accept a vector whose published bytes differ from the input, which is important for floating-point values represented as Infinity/NaN across encodings. Rows with a `loss` field do not call the helper and must not be counted as verified by this path.

**4. Manual decode utility — `sample.cpp::whatsthis()`**

```text
-e CBOR hex
  -> decode input bytes
  -> cbor_reader::parse()
  -> publish diagnostic / dump input
  -> interactive diagnostic output
  -> no fixed expected-value assertion
```

This is an inspection tool, not another conformance test.

**Coverage boundary**

The source includes selected scalar encodings, tags, arrays/maps, definite and indefinite-length structures, chunked strings, and integers beyond 64-bit limits. It does not establish full RFC 7049/8949 conformance, exhaustive malformed-input rejection, canonical encoding, or COSE interoperability.
### Documentation and verification status

The latest available aggregate report is indexed in [Test Report Snapshot](../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with **251 pass, 0 expt, 0 fail, 0 skip, 0 triv** entries for the `cbor` group. The report payload does not independently identify the tested source commit, exact compiler version, build flags, or command line. The documentation source basis is Revision 1105, distinct from that last known test-run context. This documentation update did not rerun the tests.

## 4. Relationships

- [CBOR implementation](../../../sdk/io/cbor/README.md) — object model, reader, encoder, publisher, and diagnostic/concise visitors.
- [CBOR testcase CMake configuration](CMakeLists.txt) — includes the directory's C++ sources and copies YAML assets into the build tree.
- [RFC example tests](testcase_rfc7049.cpp) — fixed known-answer encoding/publication checks.
- [YAML vector tests](testvector_cbor.cpp) and [vector data](testvector_cbor.yml) — data-driven parse/publish checks.
- [Shared test report snapshot](../test-report-status.md) — aggregate result and provenance limitations.
- `sdk/crypto/cose/` — CBOR is the message encoding used by COSE; the COSE test suite is a related consumer, not part of this directory's 251-entry report.

## 5. References

- [RFC 7049 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc7049), especially Appendix A and Table 4 examples.
- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949), especially Appendix A examples and Appendix B's initial-byte jump table.
- [RFC 8152 — CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc8152), source of several retained COSE-related YAML examples.
