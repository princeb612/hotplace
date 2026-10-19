## Publication

```text
hotplace source tree
Edition 1 · Revision 1104
Documented with GPT-6
— source structure, implementation & tests
```

# ASN.1 testcase source and verification map

## 1. Role

This document maps the main ASN.1 testcase source files to the implementation areas they exercise. It is a guide to the checked-in test code, not a claim that every case passed in a specific environment.

## 2. Test model

The suite combines table-driven DER/X.690 tests, ASN.1 object-model tests, notation parsing, module publishing, constraints, loader probes, and parameterized semantic experiments. Test vectors are also stored in YAML.

## 3. Example: X.690 identifier encoding and parsing

`testcase_basic1.cpp` defines `test_x690_8_1_2_identifier_octects()`. Positive vectors compare encoded identifier octets with expected bytes, check published notation/DER, and read identifiers back. Negative vectors expect `errorcode_t::bad_data` for incomplete or non-minimal high-tag encodings. `test_x690_8_1_3_length_octets()` covers short and long length forms.

## 4. Test and verification status

### 4.1 Source-level coverage

- **O** — explicit byte comparisons for X.690 identifier and length octets.
- **O** — invalid identifier vectors check for `bad_data`.
- **O** — `runtime/testcase_parser.cpp` supplies broad notation/constraint input cases.
- **O** — `runtime/testcase_publish.cpp`, `testcase_basic2.cpp`, `testcase_constraints.cpp`, and `loader/testcase_loader.cpp` cover separate semantic areas.
- **△** — some parser inputs are fed through `parse_notation()` without a per-input expected parse tree assertion in that function.
- **△** — `test_parameterized1()` covers direct semantic specialization; `test_parameterized2()` is disabled in the current dispatcher, so full parser → loader → publisher parameterized support is not established by that test.

### 4.2 Documentation and verification status

The provided `asn.1/report` records pass 1628, expt 40, fail 0, skip 0, triv 0. The meaning of `expt` is not inferred here. The report does not include OS, compiler, build configuration, or source revision. No tests were executed during this documentation update.

## 5. Relationships

- [`README.md`](README.md) — suite overview and vector formats
- [`basic/asn1-object-model.md`](basic/asn1-object-model.md) — object model
- [`loader/asn1_loader.md`](loader/asn1_loader.md) — loader path
- [`runtime/asn1_parser.md`](runtime/asn1_parser.md) — parsing
- [`runtime/asn1_module.md`](runtime/asn1_module.md) — module representation
- [`runtime/asn1_publisher.md`](runtime/asn1_publisher.md) — semantic publishing

## 6. References

- `test/testcase/asn.1/testcase_basic1.cpp`
- `test/testcase/asn.1/testcase_basic2.cpp`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/asn.1/testvector_der.cpp`
- `test/testcase/asn.1/testvector_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_parser.cpp`
- `test/testcase/asn.1/runtime/testcase_publish.cpp`
- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp`
