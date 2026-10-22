## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Base String Testcases

## 1. What

This directory tests general-purpose string helpers and wrappers in [`sdk/base/string`](../../../../sdk/base/string/README.md): formatting, token extraction, line handling, scanning, replacement, splitting/tokenization, Base16 conversion, runtime obfuscation, compile-time string demonstrations, callback-based printing, and `ansi_string`. On Windows, `wide_string` tests are also invoked.

The suite is mixed. Some cases compare results with expected values; others primarily print output and finish with unconditional `assert(true, ...)`. Those assertions confirm execution reached that point, not that the logged output is correct.

## 2. How

1. The main source is [`testcase_string.cpp`](testcase_string.cpp). Its top-level testcase invokes the following paths:

```text
testcase_string()
  ├─ test_string_format()          expected formatted string
  ├─ test_string_gettoken()        four expected token comparisons
  ├─ test_string_hexbin()           Base16 encode/decode, output-oriented
  ├─ test_string_constexpr_hide()   constexpr string logging/dump
  ├─ test_string_constexpr_obf()    C++14+ path; otherwise not_supported
  ├─ test_string_obfuscate_string() byte and equality comparisons
  ├─ test_string_printf()            callback output, output-oriented
  ├─ test_string_getline/scan*()     traversal output, unconditional pass
  ├─ test_string_replace/split/
  │  test_string_tokenize()          output, unconditional pass
  └─ test_string_ansi_string()       operators and rule-of-five scenarios
       └─ test_string_wide_string()  Windows only
```

### 2.1 Formatting and token extraction

1. `test_string_format()` calls `format("%s %d %1.1f", "sample", 1, 1.1f)` and compares the result with `"sample 1 1.1"`.

2. `test_string_gettoken()` uses source `"key=item1|value1|link1"` and delimiter set `"=|"`. Calls for token indices 0 through 3 must return `key`, `item1`, `value1`, and `link1` respectively. Each token has its own string equality assertion.

3. `test_string_tokenize()` uses the same input and delimiter set but repeatedly calls `tokenize()` with a moving position until it becomes `(size_t)-1`. It prints each token and ends with `assert(true)`; unlike `gettoken()`, it does not compare the emitted token sequence with an expected list.

### 2.2 Line handling, scanning, replacement, and splitting

1. These tests contain useful concrete inputs, but their current assertions are execution-only:

- `test_string_getline()` reads `" line1 \nline2 \n  line3\nline4"` with `getline()`. For each returned segment it trims leading/trailing whitespace and prints the line. It advances to `brk + 1` and stops when the helper returns a non-success code. The final assertion is unconditional; neither line count nor the four normalized strings are checked.
- `test_string_scan()` scans `"hello world\n "` for `isspace`, prints each reported position, and dumps the original bytes. The positions are not compared with expected offsets.
- `test_string_scan2()` scans `"hello world\n wide world\n"` for the substring `"world"`, prints match positions, and advances by the match length plus one. It does not assert the expected match offsets or match count.
- `test_string_replace()` replaces `"world"` with `"neighbor"` in `"hello world"` and prints the resulting string. It does not compare the result with `"hello neighbor"`.
- `test_string_split()` splits a colon-delimited list of five TLS cipher-suite names (including `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`) into indexed binary segments and prints each segment's index, size, and text. It does not check the number, order, or contents of the segments against an expected table.

2. These are important candidate cases for stronger assertions, but this document records the current source behavior rather than treating the printed output as already verified.

### 2.3 Base16 conversion, callback printing, and compile-time demonstrations

1. `test_string_hexbin()` encodes the first five bytes of `"sample"` to Base16, decodes the result into `binary_t`, and dumps the bytes. It does not compare the encoded string with a fixed value or compare the decoded bytes with the original input; its final assertion is unconditional.

2. `test_string_printf()` routes `"%s %i %1.1f"` with `"sample"`, `1`, and `1.1` through `printf_runtime()` and a callback that appends emitted chunks to `context.str`. It prints the accumulated string but does not compare it with `"sample 1 1.1"`. This differs from `test_string_format()`, which does compare the resulting string.

3. `test_string_constexpr_hide()` prints and dumps three ordinary `constexpr char[]` lyric excerpts. It does not inspect the compiled binary or otherwise demonstrate that those strings are hidden.

4. `test_string_constexpr_obf()` constructs three obfuscated strings only for C++14 and later, then reconstructs and prints them. Its assertion is unconditional. In C++11 mode, the source records `not_supported`; no compile-time obfuscation assertion is executed in that mode.

### 2.4 Runtime obfuscation and string value semantics

1. `test_string_obfuscate_string()` initializes an obfuscation wrapper from the bytes for `"hello world"`. It checks that streaming the wrapper into `binary_t` yields non-empty bytes identical to the original characters, that streaming into `std::string` yields the same bytes, and that separately initialized wrappers compare equal. After appending the same source to both wrappers, it checks equality again. These are direct byte/equality checks; the diagnostic dumps are not the assertion oracle.

2. `test_string_ansi_string()` compares two independently assembled values. On Windows the first value includes `"unicode "`; on other platforms it is assembled from `"sample "`, `uint16(1)`, and `1.1f`. The test checks equality through both the object and C-string comparison overloads, appends `" dummy"` to the second value, and checks inequality and ordering in both directions.

3. The Windows-only `test_string_wide_string()` builds `L"sample ansi c1 1.100000"` through mixed wide/narrow insertions and compares it with a separately constructed expected `wide_string`. It checks equality against both the object and `c_str()`, then appends `L" dummy"` and checks inequality and ordering.

### 2.5 Rule-of-five diagnostics and container use

1. `test_string_ansi_string()` invokes `t_test_rule_of_5<ansi_string>()`. That helper logs copy construction, copy assignment, move construction, move assignment, self-assignment, map insertion by `emplace()`, map `operator[]`, and vector growth with ten `"Temp"` values. It finishes with unconditional `assert(true)`; it does not compare the moved-from state, container contents, or destructor counts.

2. The ANSI and Windows wide-string tests also insert fruit/color pairs into `std::map` and log the ordered entries. Their final unconditional assertions explicitly point to Application Verifier logs; they do not themselves check map contents or memory safety. Treat Application Verifier as independent runtime evidence only when a corresponding run report is available.

## 3. Evidence

### Source-level coverage

**1. Formatting and token extraction**

```text
format string + arguments -> formatter -> compare expected output
input text -> token extraction/parsing -> compare selected token values/counts
```

**2. Line and string operations**

```text
string input -> scan / replace / split / line operations
  -> compare positions, counts and selected output strings
  -> logged intermediate output is diagnostic only
```

**3. Base16 callbacks and obfuscated strings**

```text
selected bytes -> Base16/callback path -> compare explicit expected result where present
obfuscated literal -> decode/access string value -> compare selected behavior
  -> compiler-version / Windows guards restrict which paths are available
```

**4. Rule-of-five and container diagnostics**

```text
copy/move/destroy operations -> lifetime messages
  -> diagnostic unless a resulting value or ownership state is asserted
```



The supplied [Test Report Snapshot](../../test-report-status.md) records the `string` group as `success 34`. These 34 report entries are not 34 unique test functions, and they do not prove the correctness of output-only cases.

The report does not identify the tested source revision, OS, compiler, or language mode. The C++14+ and Windows-gated paths must not be assumed to have run in every configuration.



## 4. Relationships

- [`sdk/base/string/README.md`](../../../../sdk/base/string/README.md) — implementation overview.
- [`sdk/base/string/string.md`](../../../../sdk/base/string/string.md) — general string operations and wrappers.
- [`sdk/base/string/split.md`](../../../../sdk/base/string/split.md) — split-context behavior.
- [`sdk/base/string/obfuscation.md`](../../../../sdk/base/string/obfuscation.md) — runtime obfuscation.
- [`sdk/base/string/constexpr-obfuscation.md`](../../../../sdk/base/string/constexpr-obfuscation.md) — language-gated compile-time experiment.
- [Test Report Snapshot](../../test-report-status.md) — aggregate execution report and provenance limitations.

## 5. References

No external reference is required to explain these testcase flows.
