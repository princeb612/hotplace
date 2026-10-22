## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# Base Stream Testcases

## 1. What

This directory contains two testcase groups for the `sdk/base/stream` area:

- **`stream`** — `basic_stream` formatting and append operations, line extraction, wide-integer formatting where supported, and byte-fragment / grouped-segment splitting.
- **`bufferio`** — context-backed buffer writes, edits, searches, comparisons, clearing, and retrieval of the underlying data pointer.

The tests use different kinds of checks. Some compare results with explicit expected values; others check operation return codes or log output for inspection. These forms of checking are not interchangeable.

## 2. How

### 2.1 Stream formatting and line handling

1. `testcase_stream.cpp` calls each test function directly through `testcase_stream()`.

| Test flow | Input and operation | What is checked |
|---|---|---|
| `test_stream_basic_stream()` | Formats a `valist` through `basic_stream::vaprintf`, then exercises `operator<<` and `operator+=` | Compares the formatted output and append results with expected strings |
| `test_stream_getline()` | Extracts lines from a string containing leading/trailing spaces and newline separators; trims each extracted line | Checks that four lines were extracted; the logged line contents are not individually compared |
| `test_stream_autoindent()` | Writes two lines after enabling two-space indentation | Compares the result with `"  test\\n  test"` |
| `test_stream_i128()` | Formats signed and unsigned 128-bit values, including minimum/maximum examples | Compares decimal output with expected strings, only when `__SIZEOF_INT128__` is defined |
| `test_stream_vtprintf()` | Formats integer and string variants through `vtprintf` | Calls the function and logs the output, but ends with an unconditional `assert(true, ...)`; the assertion does not validate the formatted result |

2. For example, the formatting test uses one shared expected value for both append interfaces:

```cpp
const char* expect = "1234hello world 3.141592";

basic_stream bs2;
bs2 << (uint8)1 << (uint16)2 << (uint32)3 << (uint64)4
    << "hello world" << ' ' << 3.141592;
_test_case.assert(bs2 == expect, __FUNCTION__, "operator <<");

basic_stream bs3;
bs3 += (uint8)1;
bs3 += (uint16)2;
bs3 += (uint32)3;
bs3 += (uint64)4;
bs3 += "hello world";
bs3 += ' ';
bs3 += 3.141592;
_test_case.assert(bs3 == expect, __FUNCTION__, "operator +=");
```

3. This checks the final string for these particular values. It does not by itself establish formatting behavior for every supported type or format specifier.

### 2.2 Fragment and segment splitting

1. The split tests build expected structures and compare the callback results against them.

- `test_stream_split()` creates a 0x410-byte input and splits it into 0x80-byte fragments. It checks both the ordinary split and a second split with an initial offset of 0x10 by comparing the collected offset/length maps.
- `test_stream_split2()` creates groups of 100, 210, 30, and 0 bytes with a segment size of 80. Its callback checks the expected segment index, group index, description, fragment offset, and fragment size for each emitted fragment.
- `test_stream_split3()` groups lengths `{200, 300, 400, 400, 50}` with a maximum segment size of 500 and compares the resulting queues with an expected grouping.

2. These assertions verify the tested layouts and grouping examples. They do not establish coverage of every input length, offset, empty-group arrangement, or production network-publishing path.

### 2.3 Object lifetime and diagnostic output

1. `test_stream_basic_stream()` invokes `t_test_rule_of_5<basic_stream>()`. The helper exercises copy/move construction and assignment, map insertion, and vector growth, but its final assertion is unconditional. The logged values are useful diagnostics; that assertion does not prove the values or object-lifetime behavior are correct. Sanitizer evidence must be taken from an actual Sanitizer run.

### 2.4 Buffer I/O operations

1. `testcase_bufferio.cpp` contains two flows:

- `test_bufferio1()` opens a context, performs formatted writes and edits, searches for characters, checks sizes and positions, compares content, clears the context, and closes it. Several intermediate operations are checked by return code. Later checks compare the `hello world` buffer with `helloworld`, then verify replacement results against `example example example` and `example sample example`.
- `test_bufferio2()` opens a context with nonzero padding, calls `get()` before writing and after clearing, and asserts that the returned data pointer is non-null in both cases. It does not explicitly check every setup or mutation return code in this function.

2. The helper `do_dump()` prints buffer contents for inspection. A dump is diagnostic output; it is not an expected-value assertion unless the test separately compares that content.

### 2.5 Scope and conditional paths

1. The `stream` and `bufferio` groups are registered separately by their respective source functions. The `__SIZEOF_INT128__` guard means the wide-integer case does not execute on every compiler/platform. The current source review did not find a direct `binary_stream` testcase in these two files; tests of `basic_stream`, `splitter`, or `binary_t` should not be presented as direct `binary_stream` coverage.

## 3. Evidence

### Source-level coverage

**1. Formatting, append and line extraction**

```text
format/append input -> stream output -> compare selected expected strings
line input -> extract lines -> compare line count
  -> extracted line contents are not all compared
```

**2. Indentation and wide integers**

```text
value + indentation/width options -> format stream -> compare expected text where asserted
128-bit path -> compiler-support guard -> only built/executed where supported
```

**3. Fragment/segment and buffer I/O**

```text
input stream -> fragment/segment split -> compare selected counts and contents
buffer -> write/edit/search/compare/clear/retrieve -> compare explicit state/fields
```

Logged buffer contents and rendered diagnostics are not golden-byte comparisons unless the source compares them.

**4. Lifetime and platform paths**

```text
object lifetime / platform demonstration -> log output or guarded operation
  -> diagnostic/conditional evidence, not universal branch coverage
```



The supplied [Test Report Snapshot](../../test-report-status.md) records the legacy aggregate results for these groups: `stream` — 27 pass entries; `bufferio` — 30 pass entries, with no failures reported in either group.

That snapshot does not identify the tested source revision, operating system, compiler, or complete build configuration. It is group-level execution evidence for the supplied report, not proof that the current Revision 1106 tree was tested, nor proof that every operation described above has an independent expected-value assertion. The source-level checks and the report outcome answer different questions, so the report is linked here rather than duplicated as a second evidence table.



## 4. Relationships

- [`testcase_stream.cpp`](testcase_stream.cpp) — stream formatting, line handling, and splitting checks.
- [`testcase_bufferio.cpp`](testcase_bufferio.cpp) — context-backed buffer I/O checks.
- [`testcase_stream.md`](testcase_stream.md) — detailed source review, including the retained maintainer note about the `dtls_record_publisher` sketch in `test_stream_split3()`.
- [`testcase_bufferio.md`](testcase_bufferio.md) — detailed source review and the intent noted for the post-clear data-pointer case.
- [`sdk/base/stream/README.md`](../../../../sdk/base/stream/README.md) — implementation overview.
- [Test Report Snapshot](../../test-report-status.md) — provenance and scope of the supplied aggregate report.

## 5. References

No external book, article, RFC, or online reference is required to explain the testcase flows described here.
