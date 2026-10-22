## Publication

~~~text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— loader path, module resolution & evidence
~~~

# ASN.1 loader testcase

## 1. What

This directory exercises the file/stream entry point that connects ASN.1 source loading to tokenization, grammar parsing, semantic publication, and the module registry. The loader deliberately remains a small entry point; it does not own the parser or publisher responsibilities.

Primary source: testcase_loader.cpp. The active testcase_loader() dispatcher calls both test_asn1loader_babystep() and test_loader(). The babystep deliberately tests load_file() and publisher construction as separate stages; test_loader() expands the path into tokenization, parse-tree creation, semantic publication, and module checks.

## 2. How

### Staged load-and-publish example

1. test_asn1loader_babystep() uses `example3.asn1` to keep file loading and semantic publication as two visible operations:

1. Call `asn1_loader::load_file()` to obtain a parse tree from the source file.
2. Pass that parse tree to the advisor-owned publisher's `build()` method.
3. Read the module names and access the resulting `MyShopPurchaseOrders` module.
4. Visit the expected definitions, including `PurchaseOrder`, `CustomerInfo`, `Address`, `ListOfItems` and `Item`.
5. Call `represent()` on the loaded module to produce a notation rendering for inspection.

2. This staged example intentionally bypasses the loader's combined convenience path after the parse tree has been obtained, so loading and publication can be examined separately.

### Multi-fixture loader procedure

1. test_loader() iterates five fixture entries, from `example1.asn1` through `example5.asn1`. Each entry declares expected module names and a per-module summary of expected symbols, exports and imports. The test then performs these operations:

1. Use `asn1file_to_tokens()` to read the fixture and produce parser tokens.
2. Pass the tokens to `to_parsetree()`.
3. Pass the parse tree to `to_result()` to build semantic module state.
4. For successful stages, look up the resulting modules and produce their notation representation.
5. Examine the module summary for each fixture, including imported symbols in the `CommonDefinitions` / `SecureMessageModule` example.

2. If tokenization, parse-tree construction or semantic publication returns an error, the loop continues to the next fixture rather than running later stages for that item. This makes the three conversion operations distinct parts of the test procedure.

### Loader boundary

1. The filesystem-facing `load_file()` entry point opens source through `file_stream`, maps the file content and forwards it into the ASN.1 parsing path. The loader itself does not own grammar parsing or semantic publication; those are delegated to `asn1_parser` and the advisor-owned `asn1_publisher`. The sibling [runtime testcase](../runtime/README.md) describes the parser and publisher test procedures.

## 3. Evidence

### Source-level coverage

**Staged loader path — testcase_loader.cpp**

~~~text
fixture file
  -> load/tokenize/parse/publish stages
  -> assert stage return statuses where checked
  -> assert actual module names against expected names
  -> assert selected module and symbol lookups
  -> assert is_resolvable() for imported/reference relationships
  -> represent() regenerated notation (logged/observable output)
  -> end
~~~

The active testcase_loader() dispatcher calls both test_asn1loader_babystep() and test_loader(). The babystep exercises the load_file() and publisher construction boundaries separately; the broader loader test checks module names, selected symbols and dependency relationships.

**What the evidence establishes**

- **Explicit comparisons/checks:** expected module names, selected module/symbol lookups and is_resolvable() checks provide assertions beyond successful parsing alone.
- **Diagnostic output only:** regenerated notation is not compared against a complete expected source string, so it is not a full semantic-equivalence assertion.
- **Coverage limits:** aggregate test results do not identify which loader subfunction or fixture passed. The tests do not prove complete grammar coverage, all malformed-input recovery behavior, semantic equivalence for every ASN.1 construct, or every dependency-resolution combination.
- **Separate disabled path:** the parameterized parser → loader → publisher probe in parameterized/testcase_parameterized.cpp remains disabled; ordinary module-loading checks do not establish parameterized integration.

### Documentation and verification status

The supplied parent ASN.1 report is aggregate and does not map results to loader functions or independently identify source revision, compiler, build flags, or command line. The last known report context is Revision 1104 · MinGW64/GCC · CTest; this documentation uses source basis Revision 1105. No tests were run during this documentation update.

## 4. Relationships

- [Parent ASN.1 testcase suite](../README.md) — overall dispatch, DER/object paths and shared report.
- [Runtime tests](../runtime/README.md) — tokenization, parsing, semantic publication and module model.
- [Loader implementation](../../../../sdk/io/asn.1/loader/asn1_loader.cpp)
- [Parser implementation](../../../../sdk/io/asn.1/runtime/asn1_parser.cpp)
- [Publisher implementation](../../../../sdk/io/asn.1/runtime/asn1_publisher.cpp)
- testcase_loader.cpp — loader testcase source.

## 5. References

- [ITU-T X.680 — ASN.1: Specification of basic notation](https://www.itu.int/rec/T-REC-X.680)
- [ITU-T X.690 — ASN.1 encoding rules: BER, CER and DER](https://www.itu.int/rec/T-REC-X.690)
- [RFC 5912 — New ASN.1 Modules for the PKIX](https://www.rfc-editor.org/rfc/rfc5912)

## 6. Developer Notes (for maintainer review)

The former child document retained a historical design note that distinguishes the earlier loader-flow sketch from the current implementation record. That distinction is preserved above. The source history records the first loader/parsing implementation at Revision 1097, import/export and reference-resolution work at Revision 1099, and provider consolidation under asn1_advisor at Revision 1100; these revision notes describe history, not present-day test evidence. Parameterized parser → loader → publisher integration remains a separate disabled probe in the wider suite and should not be inferred from ordinary module-loading checks.
