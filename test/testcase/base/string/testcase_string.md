## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# `testcase_string.cpp`

## 1. Role

This testcase file exercises the public string utilities and wrappers under `sdk/base/string`. It is a mixed test file: some functions compare concrete expected values, while others primarily print output and finish with an unconditional `assert(true, ...)`.

## 2. Test model

```text
testcase_string()
  ├─ formatting / token extraction
  ├─ line handling / scan / replace
  ├─ split context / tokenization
  ├─ runtime string obfuscation
  ├─ compile-time obfuscation (language-version gated)
  └─ ansi_string (+ wide_string on Windows)
```

## 3. Example: representative testcase flow

This document does not duplicate a standalone program. The representative testcase functions and their assertion strength are described under Source-level coverage.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Important cases and assertion strength

| Function | Intended subject | Source-level verification |
|---|---|---|
| `test_string_format()` | `format()` result | Explicit expected string comparison |
| `test_string_gettoken()` | Indexed token extraction | Four explicit token comparisons |
| `test_string_getline()` | Bounded line traversal and trimming | Output is logged; final assertion is unconditional `true` |
| `test_string_scan()` / `test_string_scan2()` | Predicate and match scanning | Positions are printed; final assertion is unconditional `true` |
| `test_string_replace()` | In-place replacement | Result is printed; final assertion is unconditional `true` |
| `test_string_split()` | Delimiter split into fragments | Fragments are printed; final assertion is unconditional `true` |
| `test_string_tokenize()` | Repeated tokenization | Tokens are printed; final assertion is unconditional `true` |
| `test_string_obfuscate_string()` | Runtime wrapper output and equality | Explicit byte/equality comparisons in several steps |
| `test_string_constexpr_hide()` | Ordinary constexpr string demonstration | Logs/dumps strings; final assertion is unconditional `true` |
| `test_string_constexpr_obf()` | C++14+ compile-time obfuscation | In supported language modes, reconstructs and prints values but final assertion is unconditional `true`; older modes report `not_supported` |
| `test_string_ansi_string()` | String operators and object-lifetime scenarios | Explicit equality/ordering checks; rule-of-five helper itself ends with unconditional `true` |
| `test_string_wide_string()` | Windows wide-string operators | Windows-only; explicit equality/ordering checks, plus a verifier-oriented logging block |
| `test_string_printf()` | `printf_runtime()` callback output | Output is logged; final assertion is unconditional `true` |
| `test_string_hexbin()` | Base16 encode/decode demonstration | Output is logged; final assertion is unconditional `true` |

This table describes the source as written, not a judgment that an API is incorrect. Logging an output is not equivalent to asserting that it matches an expected result.

#### Cross-check notes

- `test_string_getline`, `test_string_scan`, `test_string_scan2`, `test_string_replace`, `test_string_split`, `test_string_tokenize`, `test_string_printf`, and `test_string_hexbin` finish with unconditional `assert(true, ...)`. Their report rows are runtime outcomes, not independent evidence that every printed value was correct.
- `test_string_constexpr_hide()` prints and dumps ordinary `constexpr char[]` values; it does not inspect the resulting binary to prove that strings are hidden.
- The C++14+ branch of `test_string_constexpr_obf()` reconstructs and prints values, but its assertion is unconditional. The test report records a pass, which should not be interpreted as a binary-level verification of obfuscation.
- `test_string_ansi_string()` calls `t_test_rule_of_5<ansi_string>()`; the helper exercises copy/move operations and map/vector paths but ends with an unconditional assertion. Sanitizer/Application Verifier observations are separate evidence and should be recorded only when those tools' actual results are available.

### 4.2 Documentation and verification status

#### Documentation completeness

**Status: Partial.** The principal test groups and important explicit-vs-unconditional assertions are documented. This is not a line-by-line specification of every helper or every platform-specific path.

#### Verification completeness

**Status: Partial.** Several functions have explicit comparisons (`format`, `gettoken`, runtime obfuscation, string operators). Other cases exercise code but do not assert their output against an expected value. The rule-of-five helper exercises copy/move operations and container insertion/reallocation, but its final `assert(true, ...)` does not itself validate the resulting values or memory safety.

#### Runtime execution

- **Reported group:** `string`
- **Reported result:** `success 34`; the report lists 34 `pass` rows for this group.
- **Source of result:** `test/testcase/base/report` in the supplied CTest report archive.
- **Environment and source revision:** not identified by the report; this result is not attributed to revision 1104 or a particular OS/compiler.

The report includes rows for `test_string_constexpr_obf()` and `test_string_wide_string()`. Their presence establishes what the report recorded, but does not by itself identify the language mode or platform used.

#### Source basis

Edition 1 · Revision 1104 for source analysis. Runtime results are from the separately supplied report archive; the report does not identify its source revision.

## 5. Relationships

- Module documentation: [`sdk/base/string/README.md`](../../../../sdk/base/string/README.md)
- Test source: `testcase_string.cpp`
- Aggregate execution report: [`../../test-report-status.md`](../../test-report-status.md)

## 6. References

- `sdk/base/string/string.hpp`
- `sdk/base/string/split.hpp`
- `sdk/base/string/obfuscate_string.hpp`
- `sdk/base/string/constexpr_obfuscate.hpp`
