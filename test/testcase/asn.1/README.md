## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— testcase procedure, parser flow & evidence
```

# ASN.1 testcase suite

## 1. What

This directory exercises several related but distinct parts of the ASN.1 implementation under `sdk/io/asn.1/`: X.690 identifier and length encoding, ASN.1 object construction and DER publication, weakly typed DER decoding, strongly typed schema-based decoding, notation parsing and reconstruction, constraints, module loading, and parameterized-type experiments. It also contains ASN.1 schema fixtures and YAML test-vector corpora.

The test executable's `main()` first checks that the advisor's LALR(1) notation parsers and GLR parsers are ready in both build-table and imported-table forms. It then dispatches the basic encoding/object tests, constraints, DER vectors, parser tests and notation vectors, publisher, strongly typed decoding, loader, and parameterized tests. The source files cover different stages; they do not demonstrate one uniformly complete ASN.1 compiler pipeline.

| Source area | Primary responsibility |
| --- | --- |
| `testcase_basic1.cpp` | X.690 identifier and length octets, including invalid high-tag encodings |
| `testcase_basic2.cpp` | Weakly typed DER decoding, semantic promotion, object trees and re-encoding scenarios |
| `testcase_basic3.cpp` | Strongly typed schema definitions, tagged types and DER read/publish comparisons |
| `testcase_constraints.cpp` | Integer/real/string/size constraints represented by constraint objects |
| `testvector_der.cpp` + `testvector_der.yml` | YAML-driven weakly typed DER decoding |
| `testvector_parser.cpp` + `testvector_parser.yml` | DER decoding, notation reconstruction and value injection from YAML |
| `runtime/testcase_parser.cpp` | Table-driven ASN.1 notation inputs covering assignments, types, tags and constraints |
| `runtime/testcase_publish.cpp` | Parse-tree semantic construction and publication experiments |
| `loader/testcase_loader.cpp` | ASN.1 file-to-token, parse-tree, module build, exports/imports and symbol lookup |
| `parameterized/testcase_parameterized.cpp` | Direct semantic specialization prototypes; parser-to-loader integration probe remains disabled |
| Advisor/provider path | Entity dictionaries, tagging/class lookups, shared publisher and parser providers are described in the integrated sections below |

The runtime's current module representation is `asn1_module`, with the named-module registry `asn1_modules`. The earlier `asn1_module_context` name is not current in the source basis documented here.

## 2. How

### 2.1 X.690 identifier and length octets

1. `test_x690_8_1_2_identifier_octects()` in `testcase_basic1.cpp` iterates a table of identifier class, primitive/constructed bit, tag number, expected notation, and expected DER bytes.
2. For positive cases, call `asn1_encode::write_identifier()` and compare its output with the fixed expected hex.
3. Construct the corresponding ASN.1 object and compare its published notation and DER.
4. Call `read_identifier()` and check that identifier class and tag number round-trip.
5. For incomplete high-tag encodings, unterminated continuation bits, and non-minimal high-tag form, assert `errorcode_t::bad_data`.
6. `test_x690_8_1_3_length_octets()` checks short- and long-form length values around encoding boundaries using explicit expected-octet comparisons; diagnostic output is not the oracle.

### 2.2 Weakly typed DER and object-model round trips

1. In `testcase_basic2.cpp`, construct semantic ASN.1 objects for the selected X.690 structures: primitive/constructed values, implicit/explicit and chained tags, nested containers, SET ordering, long lengths, high tag numbers, SEQUENCE/SET and OF forms, CHOICE, DEFAULT, ENUMERATED, named numbers, and value binding.
2. Publish the objects to DER and feed encoded bytes through the weakly typed reader.
3. Promote the decoded TLV tree into ASN.1 objects and republish DER.
4. Compare expected structure or bytes only where the individual case defines those checks. These are selected object-model examples, not an exhaustive proof of every ASN.1 type.

### 2.3 Strongly typed schema decoding

1. In `testcase_basic3.cpp`, define named schema types with `asn1_referenced_type::define()` and create references with `refer()`.
2. Add the schema notation to an `asn1_module`.
3. Read each DER input using the expected object name, so decoding is guided by the declared schema rather than inferred only from TLV identifiers and lengths.
4. Compare the module's represented notation with the expected schema notation.
5. Republish DER and compare the resulting bytes with the original input.

### 2.4 Constraint construction and value validation

1. For each row in `testcase_constraints.cpp`, build the ASN.1 type/object and its constraint tree.
2. Publish the type as notation and compare it with the expected source or canonical notation.
3. Parse the expected notation into a module as part of the case setup.
4. Instantiate an `asn1_value` and assign the test data: integer/real scalars, strings, OCTET STRING/BIT STRING values, collections, enumerated values, or nested SEQUENCE fields.
5. Call `type->validate(value)`.
6. Use the row's `expect` flag to select `_test_case.assert(test, ...)` for valid inputs or `_test_case.nassert(test, ...)` for invalid inputs.
7. The selected cases cover single values/unions, integer and real ranges, intersections and EXCEPT/ALL EXCEPT, SIZE, permitted alphabets, string and collection sizes, ENUMERATED members, nested fields, patterns, and an exclusive boundary. They do not exhaustively enumerate the full value domain.
8. Object-level validation also checks built-in value representations for the corresponding ASN.1 entity. The reviewed cases include BOOLEAN, NULL, INTEGER, REAL, OBJECT IDENTIFIER, RELATIVE-OID, OCTET STRING, BIT STRING and supported string types; ENUMERATED validation rejects values that are not declared members.
9. Constructed SEQUENCE/SET values are traversed recursively so named child values are checked against their own types and constraints.
10. These checks are layered: basic type validation and constraint evaluation are distinct responsibilities. Do not infer complete validation of all referenced types or all ASN.1 productions from a successful fallback branch.

### 2.5 YAML DER vectors

1. `test_yaml_testvector_der()` loads `testvector_der.yml` and decodes each `der` field from hexadecimal.
2. Pass the bytes to `asn1_module::read_weakly_typed()`.
3. Check that decoding succeeds and that the consumed position equals the complete input length.
4. Emit the represented type, decoded value, and republished DER for inspection. Those dumps are not separate equality assertions in this path.

### 2.6 YAML parser and notation reconstruction

1. `test_yaml_testvector_parser()` loads `testvector_parser.yml` and reads each example's optional named values (string, integer, float, Boolean, arrays, or raw bytes).
2. Inject the values into an `asn1_value` according to their declared type.
3. Weakly decode each item's DER, check the return status and complete stream consumption, and emit the module's type/value/DER representations.
4. Pass the supplied notation to `parse_reconst_notation()`, which builds semantic objects from the parse tree.
5. Compare the published notation with the source notation. The YAML schema below describes available inputs; actual assertions are the checks in these steps.

### 2.7 Parser, publisher, loader, and advisor

1. `runtime/testcase_parser.cpp::test_asn1parser()` feeds notation snippets for assignments, built-in types, tags, nested SEQUENCE/SET/CHOICE, defaults/optional fields, constraints, and non-assignment forms to the parser.
2. Record the parse status through the testcase harness. Parse-tree printing is diagnostic and does not validate a specific tree shape unless separately compared.
3. In `runtime/testcase_publish.cpp`, construct semantic objects from parse trees and exercise publication of the resulting module/object representation.
4. In `loader/testcase_loader.cpp`, load a fixture file into a parse tree, build the result through the advisor's publisher, compare module names with an expected list, and look up expected modules and symbols.
5. Interpret the advisor as the shared provider of entity/class/tagging dictionaries and prepared parser/publisher instances. `prepare()` prepares the publisher and its basic-type/constraint handlers; the runtime-facing parser currently selects the imported GLR parser.
6. Interpret the semantic model accurately: `asn1_object` carries type/entity, parent/linkage, tag, constructed, DEFAULT/OPTIONAL, tagging and constraint information; `asn1_referenced_type::define()` creates a definition while `refer()` creates a reference; `asn1_value` stores values separately from the schema. Visitors use the model for notation, DER and constraint evaluation.

### 2.8 Parameterized ASN.1

1. In `parameterized/testcase_parameterized.cpp::test_parameterized1()`, define parameterized types and specialize them with actual type/value parameters.
2. Exercise the `Envelope` payload, `FRAME` type/maximum-length parameters, a header with default priority, and a TLV buffer with maximum capacity.
3. Supply the concrete type/value parameters and invoke specialization for each selected prototype.

### 2.9 YAML data formats consumed by the test suite

The vector schemas below describe the inputs consumed by `testvector_der.cpp` and `testvector_parser.cpp`. Actual coverage still depends on which fields the consumers read and assert; the schemas alone are not execution evidence.

##### YAML schema

* DER YAML schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: DER                 # [mandatory] "DER"
    items:
      - item: string            # [mandatory]
        der: hexstring          # [mandatory] base16 stream
````

* ASN.1 YAML schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: ASN.1               # [mandatory] "ASN.1"
    values:                     # [optional] if "values" exist, item, type, and value must be present.
      - item: string            # [mandatory]
        type: string            # [mandatory] bool/int/string/float/stringarray/intarray/any
        value:                  # depends on type. example - bool true/false, int 1, string "value", real 0.1, intarray [1, 2, 3], stringarray ["A", "B", "C"], any "base16 stream"
    items:
      - item: string            # [mandatory] ASN.1 notation
        der: hexstring          # [mandatory] base16 stream
````
## 3. Evidence

### Source-level coverage

The following paths describe what the source checks, not merely the order of operations. Each path stops at the last explicit assertion or observable output; no implicit verification is inferred between stages.

**Built-in-value DER path — testcase_basic1.cpp**

~~~text
expected DER vector
  -> encode value
  -> assert encoded DER == expected DER
  -> weakly typed decode expected DER
  -> assert decode status + full input consumption
  -> re-publish decoded object
  -> assert republished DER == expected DER
  -> end
~~~

This path checks byte equality after re-encoding. It does not decode the re-encoded buffer a second time.

**Weakly typed semantic-object path — testcase_basic2.cpp**

~~~text
construct semantic object/value
  -> publish notation and DER
  -> assert expected notation and DER (per case)
  -> weakly typed decode original DER (selected cases)
  -> promote / re-publish object tree
  -> assert republished DER equality (selected cases)
  -> end
~~~

The decode/re-publish block is conditional: schema-dependent cases skip it, and type-only cases normalize the final byte before comparison. Do not extend this assertion to every table entry.

**Schema-guided path — testcase_basic3.cpp**

~~~text
schema definition + DER input
  -> schema-guided read
  -> assert represented notation == expected schema notation
  -> assert republished DER == input DER
  -> end
~~~

This verifies decoding and re-encoding through the schema path, but not a second decode.

**YAML DER vector path — testvector_der.cpp**

~~~text
YAML DER hex
  -> weakly typed decode
  -> assert decode success
  -> assert full input consumption
  -> log decoded representation and republished DER
  -> end
~~~

The republished DER is logged, not compared with the input. Therefore this helper does not assert byte-for-byte round-trip equality.

**Notation parsing and reconstruction — runtime/testcase_parser.cpp, runtime/testcase_publish.cpp, testvector_parser.cpp**

~~~text
notation sample
  -> parser.parse()
  -> record/assert parser status
  -> parse-tree dump (diagnostic)
  -> end

notation / YAML parser vector
  -> DER decode and full-consumption checks where applicable
  -> parse_reconst_notation()
  -> parser.parse() -> publisher.build()
  -> publish semantic object as notation
  -> assert reconstructed notation == input/canonical expectation
  -> end
~~~

The shared parse_reconst_notation() helper does not separately assert the return statuses from parser.parse() or publisher.build(). The notation comparison is the effective output assertion; parse-tree and logger output are not structural assertions.

**File loading and module resolution — loader/testcase_loader.cpp**

~~~text
ASN.1 fixture
  -> assert staged load/token/parse/publish statuses
  -> assert expected module names
  -> assert selected module/symbol lookups
  -> assert is_resolvable() for dependencies
  -> represent() regenerated notation (observable output)
  -> end
~~~

The regenerated notation is not compared against a complete expected source string. The active test_asn1loader_babystep() is invoked by testcase_loader(), while the separate parameterized parser → loader → publisher probe remains disabled.

**Constraint evaluation / value validation — testcase_constraints.cpp**

~~~text
construct constrained ASN.1 type and constraint tree
  -> publish type notation
  -> assert notation == expected notation
  -> instantiate value and assign candidate data
  -> parse notation into module (test setup)
  -> type->validate(value)
  -> asn1_constraints::validate / do_validate
  -> asn1_constraint_evaluator<T>
  -> build t_set_runtime<T> from constraint nodes
  -> membership / SIZE / alphabet / pattern check
  -> return valid or invalid
  -> _test_case.assert OR _test_case.nassert
  -> release value and type
  -> end
~~~

The evaluator visits the constraint tree and produces a runtime allowed-value set through `t_set_runtime<T>`; the validation code then checks extracted values against that result (for example, numeric/string membership, container or string size, permitted alphabet, or pattern). ENUMERATED values use the object's enumeration validation path. The test's positive and negative rows use `_test_case.assert(test, ...)` and `_test_case.nassert(test, ...)` respectively, so the evidence is not limited to successful construction or notation rendering. Examples include inclusive/exclusive range values, values outside numeric and SIZE limits, disallowed characters, invalid ENUMERATED members, and nested SEQUENCE fields. The table tests selected inputs; it does not exhaustively enumerate every constraint domain or composition.

The runtime publisher's constraint table is a separate path: it parses constraint notation and asserts the reconstructed notation, which verifies construction/representation rather than evaluating candidate values.

**Parameterized types**

The active parameterized test checks direct semantic specialization through `test_parameterized1()`; it does not establish the disabled parser → loader → publisher integration path in `test_parameterized2()`.

**Coverage limits**

- Invalid identifier vectors explicitly check bad_data for selected malformed encodings; this is not exhaustive malformed-DER coverage.
- Notation parsing records status for the supplied samples, but does not assert the complete structure of every parse tree.
- The suite contains decode → re-encode assertions for selected cases, but none of the paths above establishes a general encode → decode → re-encode → re-decode sequence.
- These tests do not prove full X.690/ASN.1 conformance or exhaustive rejection of invalid input.

### Documentation and verification status

The supplied `asn.1/report` records **1,628 pass, 40 expt, 0 fail, 0 skip, 0 triv**. The shared [Test Report Snapshot](../test-report-status.md) associates the last known run with **Revision 1104 · MinGW64/GCC · CTest** based on the conversation's run context; the report itself does not independently identify the tested source commit, exact compiler version, build flags or command line. The meaning of `expt` is not inferred. This documentation uses Revision 1105 as its source basis, which is distinct from that last known test-run context. No tests were executed during this documentation update.

## 4. Relationships

- [ASN.1 implementation overview](../../../sdk/io/asn.1/README.md) — runtime implementation and data model.
- [Runtime tests](runtime/README.md) — parser, publisher, module representation, resolution, and verification paths.
- [Loader tests](loader/README.md) — file loading, module imports/exports and reference resolution.
- [DER vectors](testvector_der.yml) and [parser vectors](testvector_parser.yml) — fixture inputs.
- [Test report snapshot](../test-report-status.md) — aggregate results and provenance limitations.

## 5. References

- [ITU-T X.690 — ASN.1 encoding rules: BER, CER and DER](https://www.itu.int/rec/T-REC-X.690)
- [RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 5912 — New ASN.1 Modules for the PKIX](https://www.rfc-editor.org/rfc/rfc5912)

## 6. Developer Notes

The following material is retained as developer working notes rather than normative testcase procedure: a `pyasn1` scratch example, certificate DER and third-party decoder output, and reference-decoder links. The YAML field contracts used by the active vector consumers are documented under `2. How`.

### Preserved source material

The ASN.1 runtime representation is now `asn1_module`; the singleton registry for named modules is `asn1_modules`. The former `asn1_module_context` name is not current in Revision 1105.

Parameterized ASN.1 has two distinct workstreams in this revision. The LALR/GLR grammar and binary parsing tables are at revision 3, while `parameterized/testcase_parameterized.cpp` actively exercises direct semantic prototypes through `test_parameterized1()` (`define()`, `specialize()`, and parameter values). The parser → loader → publisher probe (`test_parameterized2()`) remains disabled in `testcase_parameterized()`. This is progress beyond grammar-only work, but it is not complete end-to-end parameterized ASN.1 support.

##### references

* [ASN.1 JavaScript decoder](https://lapo.it/asn1js/)
* [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php)

##### using pyasn1

from pyasn1.type import univ
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
import binascii

encode(univ.Integer(1)).hex()
encode(univ.Real(0.0)).hex()

print("Decoded Integer:", decode(binascii.unhexlify('020100'), asn1Spec=univ.Integer()))
print("Decoded REAL:", decode(binascii.unhexlify('0900'), asn1Spec=univ.Real()))

##### ASN.1 DER

- RFC 2459 Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- RFC 3039 Internet X.509 Public Key Infrastructure Qualified Certificates Profile
- RFC 3280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- RFC 5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- RFC 5912 New ASN.1 Modules for the Public Key Infrastructure Using X.509 (PKIX)

DER
````
3082 0287 3082 020d a003 0201 0202 1454
62ff be6d 4b20 ec20 483b 13c7 736a d5ad
afae 9630 0a06 082a 8648 ce3d 0403 0230
5931 0b30 0906 0355 0406 1302 4b52 310b
3009 0603 5504 080c 024b 4e31 0b30 0906
0355 0407 0c02 474a 310d 300b 0603 5504
0a0c 0454 6573 7431 0d30 0b06 0355 040b
0c04 5465 7374 3112 3010 0603 5504 030c
0954 6573 7420 526f 6f74 301e 170d 3236
3035 3133 3232 3230 3032 5a17 0d32 3730
3531 3332 3232 3030 325a 3058 310b 3009
0603 5504 0613 024b 5231 0b30 0906 0355
0408 0c02 4b4e 310b 3009 0603 5504 070c
0247 4a31 0d30 0b06 0355 040a 0c04 5465
7374 310d 300b 0603 5504 0b0c 0454 6573
7431 1130 0f06 0355 0403 0c08 7465 7374
2e63 6f6d 3076 3010 0607 2a86 48ce 3d02
0106 052b 8104 0022 0362 0004 b27f 4ac8
e326 6939 f428 1dd9 02d4 274a 4009 74f4
7a29 e48b 3664 2e67 3398 0c59 06e4 fbce
12b6 4e87 7af0 66b2 4edb c6d7 192c be21
74f8 fa9f cb4d 8f7b 0772 5950 a11e a460
d127 b616 7106 1fe1 e17a a7cd 0047 d9b8
3ad0 edb7 c275 5e1d 151e cc5b a381 9630
8193 3009 0603 551d 1304 0230 0030 0b06
0355 1d0f 0404 0302 0780 3013 0603 551d
2504 0c30 0a06 082b 0601 0505 0703 0130
2406 0355 1d11 041d 301b 8208 7465 7374
2e63 6f6d 8209 6c6f 6361 6c68 6f73 7487
047f 0000 0130 1d06 0355 1d0e 0416 0414
f06a 5451 f417 33fc 377f 66b1 94d7 c56a
78e2 f032 301f 0603 551d 2304 1830 1680
146c b3f5 87bf 38ee dfdc 8697 57c6 9169
ea01 2313 4e30 0a06 082a 8648 ce3d 0403
0203 6800 3065 0230 4c34 053f 7cd0 3415
f9d2 3553 680c 780d db13 e70c dcc8 861f
a9cc 8767 e771 119d 0a91 29a8 8bb5 aa14
004c a1a9 eaec 43d9 0231 00ac f1ef 2fd5
dd2f e9a1 74b1 7a51 3846 c3fc 6c30 f112
3f47 ceff fc94 a35e 8051 6b77 8cfc 942d
3d45 1aa7 5ee2 9341 7d1b 57
````

ASN.1 (https://lapo.it/asn1js/)
````
- Certificate SEQUENCE (3 elem)
  - tbsCertificate TBSCertificate SEQUENCE (8 elem)
    - version [0] (1 elem)
      - Version INTEGER 2
    - serialNumber CertificateSerialNumber INTEGER (159 bit) 481762976210496776494547987657568328811820330646
    - signature AlgorithmIdentifier SEQUENCE (1 elem)
      - algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    - issuer rdnSequence Name SEQUENCE (6 elem)
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          - value AttributeValue [?] PrintableString KR
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
          - value AttributeValue [?] UTF8String KN
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          - value AttributeValue [?] UTF8String GJ
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test Root
    - validity Validity SEQUENCE (2 elem)
      - notBefore utcTime Time UTCTime 2026-05-13 22:20:02 UTC
      - notAfter utcTime Time UTCTime 2027-05-13 22:20:02 UTC
    - subject rdnSequence Name SEQUENCE (6 elem)
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          - value AttributeValue [?] PrintableString KR
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
          - value AttributeValue [?] UTF8String KN
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          - value AttributeValue [?] UTF8String GJ
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
          - value AttributeValue [?] UTF8String Test
      - RelativeDistinguishedName SET (1 elem)
        - AttributeTypeAndValue SEQUENCE (2 elem)
          - type AttributeType OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          - value AttributeValue [?] UTF8String test.com
    - subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
      - algorithm AlgorithmIdentifier SEQUENCE (2 elem)
        - algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
        - parameters ANY OBJECT IDENTIFIER 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
      - subjectPublicKey BIT STRING (776 bit) 0000010010110010011111110100101011001000111000110010011001101001001110…
    - extensions [3] (1 elem)
      - Extensions SEQUENCE (6 elem)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
          - extnValue OCTET STRING (2 byte) 3000
            - SEQUENCE (0 elem)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
          - extnValue OCTET STRING (4 byte) 03020780
            - BIT STRING (1 bit) 1
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.37 extKeyUsage (X.509 extension)
          - extnValue OCTET STRING (12 byte) 300A06082B06010505070301
            - SEQUENCE (1 elem)
              - OBJECT IDENTIFIER 1.3.6.1.5.5.7.3.1 serverAuth (PKIX key purpose)
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
          - extnValue OCTET STRING (29 byte) 301B8208746573742E636F6D82096C6F63616C686F737487047F000001
            - SEQUENCE (3 elem)
              - [2] (8 byte) test.com
              - [2] (9 byte) localhost
              - [7] (4 byte) 7F000001
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
          - extnValue OCTET STRING (22 byte) 0414F06A5451F41733FC377F66B194D7C56A78E2F032
            - OCTET STRING (20 byte) F06A5451F41733FC377F66B194D7C56A78E2F032
        - Extension SEQUENCE (2 elem)
          - extnID OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
          - extnValue OCTET STRING (24 byte) 301680146CB3F587BF38EEDFDC869757C69169EA0123134E
            - SEQUENCE (1 elem)
              - [0] (20 byte) 6CB3F587BF38EEDFDC869757C69169EA0123134E
    - signatureAlgorithm AlgorithmIdentifier SEQUENCE (1 elem)
      - algorithm OBJECT IDENTIFIER 1.2.840.10045.4.3.2 ecdsaWithSHA256 (ANSI X9.62 ECDSA algorithm with SHA256)
    - signature BIT STRING (824 bit) 0011000001100101000000100011000001001100001101000000010100111111011111…
      - SEQUENCE (2 elem)
        - INTEGER (383 bit) 1172874671356386011406782248119134935953212620868109242094972487151862…
        - INTEGER (384 bit) 2661868033690839064267418140220413291119663050155277319931341815934778…
````

ASN.1 (https://holtstrom.com/michael/tools/asn1decoder.php)
````
SEQUENCE {
   SEQUENCE {
      [0] {
         INTEGER 0x02 (2 decimal)
      }
      INTEGER 0x5462ffbe6d4b20ec20483b13c7736ad5adafae96
      SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
      }
      SEQUENCE {
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.6 (countryName)
               PrintableString 'KR'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.8 (stateOrProvinceName)
               UTF8String 'KN'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.7 (localityName)
               UTF8String 'GJ'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.10 (organizationName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.11 (organizationalUnitName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.3 (commonName)
               UTF8String 'Test Root'
            }
         }
      }
      SEQUENCE {
         UTCTime '260513222002Z'
         UTCTime '270513222002Z'
      }
      SEQUENCE {
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.6 (countryName)
               PrintableString 'KR'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.8 (stateOrProvinceName)
               UTF8String 'KN'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.7 (localityName)
               UTF8String 'GJ'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.10 (organizationName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.11 (organizationalUnitName)
               UTF8String 'Test'
            }
         }
         SET {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.4.3 (commonName)
               UTF8String 'test.com'
            }
         }
      }
      SEQUENCE {
         SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
            OBJECTIDENTIFIER 1.3.132.0.34 (P-384)
         }
         BITSTRING 0x04b27f4ac8e3266939f4281dd902d4274a400974f47a29e48b36642e6733980c5906e4fbce12b64e877af066b24edbc6d7192cbe2174f8fa9fcb4d8f7b07725950a11ea460d127b61671061fe1e17aa7cd0047d9b83ad0edb7c2755e1d151ecc5b : 0 unused bit(s)
      }
      [3] {
         SEQUENCE {
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.19 (basicConstraints)
               OCTETSTRING 3000
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.15 (keyUsage)
               OCTETSTRING 03020780
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.37 (extKeyUsage)
               OCTETSTRING 300a06082b06010505070301
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.17 (subjectAltName)
               OCTETSTRING 301b8208746573742e636f6d82096c6f63616c686f737487047f000001
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.14 (subjectKeyIdentifier)
               OCTETSTRING 0414f06a5451f41733fc377f66b194d7c56a78e2f032
            }
            SEQUENCE {
               OBJECTIDENTIFIER 2.5.29.35 (authorityKeyIdentifier)
               OCTETSTRING 301680146cb3f587bf38eedfdc869757c69169ea0123134e
            }
         }
      }
   }
   SEQUENCE {
      OBJECTIDENTIFIER 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
   }
   BITSTRING 0x306502304c34053f7cd03415f9d23553680c780ddb13e70cdcc8861fa9cc8767e771119d0a9129a88bb5aa14004ca1a9eaec43d9023100acf1ef2fd5dd2fe9a174b17a513846c3fc6c30f1123f47cefffc94a35e80516b778cfc942d3d451aa75ee293417d1b57 : 0 unused bit(s)
}
````

### Original working-status checklist

The original README contains a working-status checklist for ASN.1 Runtime, Compiler, Schema Loader, and Repository, plus reference-decoder links, YAML schema examples, a `pyasn1` scratch example, and a DER certificate vector. These items are preserved below for maintainer review; the checklist is not a claim that the listed components are absent or complete.
