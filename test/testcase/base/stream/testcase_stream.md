## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1106                    │
│ Source basis: Revision 1106                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Stream Testcases (`testcase_stream.cpp`)

## 1. What is tested?
`testcase_stream.cpp` exercises the in-memory stream and segmentation utilities under `sdk/base/stream`. It is a behavioral test source, not an API reference: each test function demonstrates a concrete contract through inputs, expected output, or assertions.

## 2. How is it tested?
1. The file covers several related areas rather than one class only:

- integer and formatted text output (`test_stream_i128`, `test_stream_basic_stream`, `test_stream_vtprintf`)
- line extraction and indentation (`test_stream_getline`, `test_stream_autoindent`)
- object lifetime behavior (`t_test_rule_of_5`, invoked by `test_stream_basic_stream`)
- splitting and segmented output (`test_stream_split`, `test_stream_split2`, `test_stream_split3`)

```text
input / operation
       |
       v
stream or splitter API
       |
       v
observed output / offsets / descriptors
       |
       v
_test_case.assert(...) or diagnostic-only check
```

2. This diagram describes the general test pattern in this file; individual tests do not all use the same assertion strength.

### Representative flow: formatted output

3. `test_stream_basic_stream()` constructs a `valist`, writes formatted values through `basic_stream::vaprintf`, and compares the resulting string with an expected literal. It then checks the insertion (`operator<<`) and append (`operator+=`) paths against a shared expected string.

```cpp
basic_stream bs;
valist va;
va << 256 << "hello world" << 3.141592;
bs.vaprintf(
    R"(value={1:04x}, value="{2:-15s}", value={3:le})", va);
_test_case.assert(
    bs == R"(value=0x0100, value="hello world    ", value=3.141592e+00)",
    __FUNCTION__, "format string syntax");
```

4. This is an excerpt of the existing testcase, not a standalone program; it relies on the test harness and declarations from `sample.hpp`.

## 3. What does the evidence establish?
### Source-level evidence
1. The source-level status below is documented against Revision 1105. Runtime evidence is recorded separately from the supplied CTest-generated report snapshot; the report does not identify the tested source revision or execution environment.

2. Status meanings:

- **O** — an explicit expected-value assertion is present in the inspected testcase.
- **△** — coverage is partial, indirect, or includes a diagnostic/smoke assertion rather than a meaningful expected-value comparison.
- **X** — no explicit check was found for the stated behavior in the inspected testcase. This does not mean the implementation fails.
- **Not run** — use this label only when no applicable execution report or run result is available; the supplied snapshot does provide group-level runtime evidence for these two cases.

| Test function / area | What the source checks | Source-level status |
|---|---|:---:|
| `test_stream_i128()` | Signed and unsigned wide-integer formatting, including boundary values, where `__SIZEOF_INT128__` is available | O |
| `test_stream_getline()` | Extracts four lines and checks the resulting line count | O |
| `t_test_rule_of_5()` via `test_stream_basic_stream()` | Copy/move and vector reallocation behavior; final assertion is `assert(true, ..., "see sanitize log")` | △ |
| `test_stream_basic_stream()` | Formatted output, `operator<<`, and `operator+=` output comparisons | O |
| `test_stream_vtprintf()` | Calls `vtprintf` for integer and string variants; final assertion is unconditional `true` | △ |
| `test_stream_autoindent()` | Output after enabling two-space indentation | O |
| `test_stream_split()` | Expected fragment offset/size maps for two split cases | O |
| `test_stream_split2()` | Descriptor/group/segment/fragment details through callback assertions | O |
| `test_stream_split3()` | Expected segmentation container comparison | O |

3. The table is deliberately limited to checks visible in `testcase_stream.cpp`. The report snapshot adds runtime evidence for the named `stream` report group, but does not prove that every platform-specific branch ran or that this file alone covers the entire stream module. See the [test report snapshot](../../test-report-status.md) for the scope and limitations of the supplied reports.

### Evidence status and limitations
| Axis | Status | Basis |
|---|---|---|
| Documentation completeness | Partial | The major test groups and visible assertions are mapped here, but this is not an exhaustive inventory of every branch or platform-specific path. |
| Verification completeness | Partial | Several functions compare explicit expected values; `test_stream_vtprintf()` and the rule-of-five helper end with unconditional `true` assertions, so those assertions alone do not validate the produced value or lifetime behavior. |
| Runtime execution | Pass (reported group) | The supplied `test/testcase/base/report` contains `@ test case "stream" success 27`; the stream group lists 27 `pass` results and no `fail` result. This is group-level evidence, not a separate runtime result for every helper/function listed above. |

4. `Documentation completeness` describes this document's coverage of the inspected source. `Verification completeness` describes the strength of the checks present in the test source. The first two axes do not establish a runtime pass; runtime status is supported separately by the report evidence above.

## Relationships
- Module behavior: [`sdk/base/stream/basic_stream.md`](../../../../sdk/base/stream/basic_stream.md)
- Segmentation behavior: [`sdk/base/stream/splitter.md`](../../../../sdk/base/stream/splitter.md)
- Test source: [`testcase_stream.cpp`](testcase_stream.cpp)
- Related buffer I/O tests: [`testcase_bufferio.cpp`](testcase_bufferio.cpp)
- Module overview: [`sdk/base/stream/README.md`](../../../../sdk/base/stream/README.md)

## References

