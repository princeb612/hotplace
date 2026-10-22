## Publication

~~~text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— parser, publisher, module model & verification
~~~

# ASN.1 runtime testcase

## 1. What

This directory tests the ASN.1 notation/runtime boundary in three distinct stages: syntax parsing, semantic publication from a parse tree, and storage/resolution of the resulting module and object model.

| Source | Focus |
| --- | --- |
| testcase_parser.cpp | Notation samples, assignments, built-in and constructed types, tags and constraints |
| testcase_publish.cpp | Publisher basics, semantic objects, constraints and staged publishing |
| Parent testcase_basic2.cpp / testcase_basic3.cpp | Object-model behavior, weakly typed decoding, schema-guided decoding and reference resolution |
| loader/testcase_loader.cpp | File-to-module path, imports/exports, symbol lookup and resolvability |

The runtime directory is not the only source of runtime-model coverage. The current runtime module representation is asn1_module, and the named-module registry is asn1_modules.

## 2. How

### Notation parser tests

1. testcase_parser.cpp calls test_asn1parser(), which creates an LALR(1) ASN.1 parser and iterates a table of notation strings. The inputs include type assignments, built-in types, tags, nested SEQUENCE/SET/CHOICE forms, DEFAULT/OPTIONAL fields, and constraint expressions. A second group supplies type fragments without assignment names. Each item is passed to parse_notation() with a fresh asn1_module, so the testcase exercises the parser across a broad set of syntactic forms without reusing a semantic module between table entries.

### Publisher and notation reconstruction

1. testcase_publish.cpp has three active parts:

1. **Babystep:** constructs a parse_tree manually using explicit shift/reduce events for `Type1 ::= VisibleString`, then sends that tree to the shared ASN.1 publisher and publishes the resulting semantic object as notation.
2. **Basic notation table:** iterates assignments and fragments covering built-in types, tags, constructed types, collections, enumerations, CHOICE, DEFAULT/OPTIONAL and ANY. Each input is parsed and the resulting semantic object is published back to notation.
3. **Constraint table:** parses integer/real ranges, unions, intersections, EXCEPT, SIZE and permitted-alphabet expressions, as well as nested and boundary forms. The table supplies a canonical expected notation for cases where reconstruction normalizes the source spelling.

2. The shared parse_reconst_notation() helper performs parsing, invokes the publisher on the parse tree, and publishes the resulting object into a basic_stream. The helper accepts an optional expected canonical string; without one, the input notation is used as the expected output.

### Module model used by these tests

1. The publisher consumes a parse_tree rather than source text. Its visitor processes shift/reduce events and dispatches grammar handlers to construct module/type/constraint objects. The resulting asn1_build_resultset contains the module names and semantic object state used by the tests.

2. The named-module registry is represented by asn1_modules, and each asn1_module stores definitions plus module-level state such as tagging defaults, exports, imports and linkage. Local lookup, imported-symbol lookup, reference resolution and linkage propagation are distinct operations: search() locates definitions, resolve() follows references, and update_linkage() propagates relationships through tagged or constructed objects. File-based module-resolution test procedures and their explicit checks are described in the sibling [loader testcase](../loader/README.md).

## 3. Evidence

### Source-level coverage

**Parser status path — testcase_parser.cpp**

~~~text
notation sample
  -> parse_notation()
  -> parser.parse()
  -> _test_case.test(return_status)
  -> diagnostic parse-tree output
  -> end
~~~

The test records parser status for each table sample. Parse-tree output is diagnostic; the cases do not independently assert each tree's structure or semantic equivalence.

**Publisher and notation-reconstruction path — testcase_publish.cpp**

~~~text
hand-built parse tree or parsed notation
  -> publisher.build()
  -> semantic object
  -> publish object as notation
  -> assert reconstructed notation == input/canonical expectation
  -> end
~~~

The active dispatcher calls test_publish_babystep(), test_publish_basics() and test_publish_constraints(). The babystep asserts the published notation Type1 ::= VisibleString. Table cases use parse_reconst_notation(), which compares reconstructed notation with the input or a canonical expected form. That helper does not separately assert parser.parse() or publisher.build() return statuses; the output comparison is the effective assertion.

**Module and reference-resolution path**

~~~text
local/imported module definitions
  -> search() / resolve()
  -> update_linkage() where invoked
  -> is_resolvable() checks in loader tests
  -> represent() regenerated notation
  -> end
~~~

These responsibilities are exercised across runtime, loader and object-model tests, not as one assertion-complete path in every testcase. Regenerated notation is not by itself a full semantic-equivalence assertion.

**DER integration boundary**

The concrete DER checks are documented in the parent [ASN.1 testcase suite](../README.md). Selected cases compare expected bytes after decode/re-encode, but the reviewed paths do not perform a final decode of the re-encoded output. Do not describe them as complete encode → decode → re-encode → re-decode tests.

**Constraint construction versus value validation**

The constraint cases in `testcase_publish.cpp` exercise the parser → publisher → notation path: constraint syntax is converted into semantic objects, then the published notation is compared with the input or a canonical expected form. This is evidence for parsing, construction and representation only; it does not validate candidate values against those constraints.

Candidate-value validation is exercised separately by `test/testcase/asn.1/testcase_constraints.cpp`, which instantiates constrained types, assigns valid and invalid values, calls `type->validate(value)`, and asserts the expected acceptance/rejection. The parent [ASN.1 testcase suite](../README.md) documents that validation path and its coverage limits.

**Other coverage limits**

- Positive notation samples cover selected assignments, tags, constructed types and constraints; exhaustive grammar or parse-tree shape coverage is not established.
- test_parameterized1() tests direct semantic specialization. The parser → loader → publisher probe test_parameterized2() is not enabled in the active dispatcher, so end-to-end parameterized parsing and instantiation remain unverified.
- The tests do not establish full X.690 conformance, exhaustive malformed-input recovery, or complete semantic equivalence of regenerated notation.

### Documentation and verification status

The supplied ASN.1 report is aggregate at the parent-suite level and does not isolate runtime parser, publisher or module functions. The last known report context is Revision 1104 · MinGW64/GCC · CTest; the source basis here is Revision 1105. No tests were run during this documentation update.

## 4. Relationships

- [Parent ASN.1 testcase suite](../README.md) — overall test dispatch, DER round trips and report snapshot.
- [Loader testcase](../loader/README.md) — file loading and module dependency checks.
- [ASN.1 implementation runtime](../../../../sdk/io/asn.1/runtime/README.md)
- [ASN.1 parser implementation](../../../../sdk/io/asn.1/runtime/asn1_parser.cpp)
- [ASN.1 publisher implementation](../../../../sdk/io/asn.1/runtime/asn1_publisher.cpp)
- [Module implementation](../../../../sdk/io/asn.1/runtime/asn1_module.cpp)
- testcase_parser.cpp and testcase_publish.cpp — testcase sources.

## 5. References

- [ITU-T X.680 — ASN.1: Specification of basic notation](https://www.itu.int/rec/T-REC-X.680)
- [ITU-T X.681 — Information object specification](https://www.itu.int/rec/T-REC-X.681)
- [ITU-T X.690 — ASN.1 encoding rules: BER, CER and DER](https://www.itu.int/rec/T-REC-X.690)
- [RFC 5912 — New ASN.1 Modules for the PKIX](https://www.rfc-editor.org/rfc/rfc5912)

## 6. Developer Notes (for maintainer review)

The former parser/publisher child documents contained implementation-status and GPT-review notes. Their relevant boundary is retained here: grammar productions for parameterized notation and direct semantic specialization are not equivalent to enabled end-to-end parameterized parsing and instantiation. The current module name is asn1_module; the old asn1_module_context name is not current in the documented source basis.
