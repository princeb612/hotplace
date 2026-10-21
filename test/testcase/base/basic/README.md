## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Base basic testcase directory

This README is the consolidated source-level testcase guide for this directory. It combines the former overview and detailed analysis so test intent, representative behavior, assertion strength, and report evidence can be read together.

## 1. Role

This directory contains tests and test vectors for the general-purpose utilities in [`sdk/base/basic`](../../../../sdk/base/basic/README.md). It covers pool allocation, command-line option registration, memory-dump formatting, function-pipeline control flow, dynamic formatting arguments, and typed runtime values.

## 2. Test model

The tests mix direct assertions in C++ testcase functions with data-driven command-line and formatting vectors. The source files are not equally strong: some compare produced values with explicit expectations, while others primarily print diagnostic output.

| Test source | Main behavior | Verification shape |
|---|---|---|
| [`testcase_builtinmemory.cpp`](testcase_builtinmemory.cpp) | Pool allocation and allocator behavior | Inspect explicit checks alongside allocation/logging cases |
| [`testcase_cmdline.cpp`](testcase_cmdline.cpp) + [`testvector_cmdline.yml`](testvector_cmdline.yml) | Required/optional arguments, values, invalid tokens | C++ harness plus vector-driven accept/reject cases |
| [`testcase_dumpmemory.cpp`](testcase_dumpmemory.cpp) | Diagnostic rendering of bytes | Primarily output-oriented; rendered text should not be assumed asserted unless a comparison is present |
| [`testcase_pipeline.cpp`](testcase_pipeline.cpp) | Conditional callback execution | Recorded callback path and result state |
| [`testcase_valist.cpp`](testcase_valist.cpp) + [`testvector_valist.yml`](testvector_valist.yml) | Heterogeneous arguments and formatted output | Expected formatted values for selected cases |
| [`testcase_variant.cpp`](testcase_variant.cpp) | Typed value conversion to bytes | Explicit Base16 string comparisons for selected conversions |

## 3. Example: pipeline path and typed value conversion

In `testcase_pipeline.cpp`, callbacks append markers to a path string. The test compares the observed sequence with an expected path to distinguish normal, failure-only, and always-run steps. This checks control flow rather than merely confirming that the pipeline returned.

In `testcase_variant.cpp`, a `uint32` value is converted with `variant_convendian | variant_trunc`, then Base16-encoded and compared with `00008000`. The test makes the selected conversion flags and resulting bytes visible in the expected value.

## 4. Test and verification status

### 4.1 Source-level coverage

The source set covers the component families listed above, but that does not mean every branch or edge case has a meaningful assertion. In particular, output-oriented tests should be treated as demonstrations unless the source compares output against a fixed expectation. The command-line vectors should be read together with the code that loads and evaluates them. Constant-true assertions do not independently validate diagnostic output.

### 4.2 Documentation and verification status

This README describes source-level intent and assertion shape. Report-visible counts include `cmdline` 12, `valist` 41, and `variant` 7 successful cases. The report lists `pipeline` as `success 6` with `expt 2`; these categories are retained as reported rather than reinterpreted. Dump-memory groups include `string`, `binary_t`, and `dump blank`. These counts are recorded cases, not distinct C++ test functions. Runtime evidence belongs to the supplied report and the central [Test Report Snapshot](../../test-report-status.md); the report does not identify the OS, compiler, build configuration, or exact source revision.

## 5. Relationships

- [`sdk/base/basic/README.md`](../../../../sdk/base/basic/README.md) — implementation roles and cross-component relationships.
- [Base testcase overview](../README.md) — aggregate suite and report provenance.
- [`CMakeLists.txt`](../CMakeLists.txt) — collects this directory's C++ sources and YAML data into the base testcase target.
- [`testcase_pipeline.cpp`](testcase_pipeline.cpp) and [`testcase_variant.cpp`](testcase_variant.cpp) — representative source flows; the first checks callback-path behavior, while the second compares converted bytes with expected Base16 text.
- [`testcase_builtinmemory.cpp`](testcase_builtinmemory.cpp), [`testcase_cmdline.cpp`](testcase_cmdline.cpp), [`testvector_cmdline.yml`](testvector_cmdline.yml), [`testcase_dumpmemory.cpp`](testcase_dumpmemory.cpp), [`testcase_valist.cpp`](testcase_valist.cpp), and [`testvector_valist.yml`](testvector_valist.yml) — other source/vector pairs described in the Test model table.

## 6. References

No external standard or publication is needed to explain these testcase flows. The implementation and test-vector relationships are documented above.
