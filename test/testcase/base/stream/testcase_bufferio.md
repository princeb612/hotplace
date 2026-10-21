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

# Buffer I/O Testcases (`testcase_bufferio.cpp`)

## 1. Role

This testcase source exercises the low-level `bufferio` API in `sdk/base/stream/lowlevel`. Unlike a module reference, this document records what the inspected tests check and how strong that evidence is.

## 2. Test model

The file has two test functions:

- `test_bufferio1()` exercises context creation, formatted writes, replacement, insertion, cutting, searching, size reporting, comparison, clearing, and closing.
- `test_bufferio2()` exercises retrieval of a non-null data pointer when the context is opened with a nonzero padding size, both before writing and after clearing.

```text
create context
    |
    v
write / edit / search / compare
    |
    v
explicit expected-value assertions
    |
    v
close context

separate case: pad_size != 0 -> get() after open and clear -> non-null pointer
```

## 3. Example: edit operations and expected content

In `test_bufferio1()`, the test writes `hello world`, checks the length and several search positions, removes the space, then compares the content with `helloworld`.

```cpp
bio.printf(handle, "hello world");
bio.size(handle, &len);
_test_case.assert((11 == len), __FUNCTION__, "size");

pos = bio.find_first_of(handle, "world");
_test_case.assert((6 == pos), __FUNCTION__, "find_first_of -> %i", pos);

ret = bio.cut(handle, bio.find_first_of(handle, isspace), 1);
_test_case.test(ret, __FUNCTION__, "cut");

std::string sample("helloworld");
test = bio.compare(handle, sample.c_str(), sample.size());
_test_case.assert((true == test), __FUNCTION__, "compare");
```

This excerpt is taken from the test's flow and depends on setup in `test_bufferio1()`. The `_test_case.test()` calls check operation results; the `_test_case.assert()` calls shown here check expected values.

## 4. Test and verification status

### 4.1 Source-level coverage

The source-level status is documented against Revision 1105. Runtime status is recorded separately from the supplied CTest-generated report snapshot; that report does not identify the tested source revision or execution environment.

- **O** — an explicit check supports the stated claim: either an expected-value assertion or a checked operation result, as described in the evidence column.
- **△** — the operation is exercised or diagnostic output is produced, but the stated content/behavior is not directly compared with an expected value.
- **X** — no explicit check for the stated behavior was found in this file; this is not a claim that the implementation fails.

| Test function / behavior | Evidence visible in source | Source-level status |
|---|---|:---:|
| `test_bufferio1()` — operation return codes | `_test_case.test(ret, ...)` is used for several operations, including open, printf, replace, cut, insert, write, clear, and close | O |
| `test_bufferio1()` — initial formatted output | Output is dumped after `printf()` / `vprintf()`, but the resulting formatted text is not compared with an expected string at those points | △ |
| `test_bufferio1()` — size and search positions for `hello world` | Asserts length `11`, positions `6`, `5`, `6`, `5`, and whitespace position `5` | O |
| `test_bufferio1()` — cut and resulting `helloworld` content | Checks the cut return code, length `10`, and `compare()` against `helloworld` | O |
| `test_bufferio1()` — replacement behavior | Compares the content against `example example example`, then checks one replacement with `run_once` against `example sample example` | O |
| `test_bufferio2()` — `get()` returns non-null storage after open and clear with `pad_size = 1` | Explicit non-null assertions after both calls to `get()` | O |
| `test_bufferio2()` — return codes for setup and mutations | `open()`, `printf()`, `clear()`, and `close()` return values are not explicitly checked in this function | △ |

### 4.2 Documentation and verification status

| Axis | Status | Basis |
|---|---|---|
| Documentation completeness | Partial | The main test flows and visible assertions are mapped here; the document does not enumerate every internal branch or platform-specific behavior. |
| Verification completeness | Partial | Several behaviors have explicit expected-value assertions, while the initial formatted output is diagnostic-only and some operations in `test_bufferio2()` have unchecked return values. |
| Runtime execution | Pass (reported group) | The supplied `test/testcase/base/report` contains `@ test case "bufferio" success 30`; the bufferio group lists 30 `pass` results and no `fail` result. |

`Documentation completeness` evaluates how well this document explains the inspected test source. `Verification completeness` evaluates the test evidence visible in the source; neither status substitutes for the separate report-backed runtime result.

## 5. Relationships

- Test source: [`testcase_bufferio.cpp`](testcase_bufferio.cpp)
- Module description: [`sdk/base/stream/lowlevel-bufferio.md`](../../../../sdk/base/stream/lowlevel-bufferio.md)
- Related module: [`sdk/base/stream/basic_stream.md`](../../../../sdk/base/stream/basic_stream.md)
- Related tests: [`testcase_stream.cpp`](testcase_stream.cpp)

## 6. References

- Revision basis: hotplace source archive, revision 1104.
- Test implementation: `test/testcase/base/stream/testcase_bufferio.cpp`.
- Runtime evidence for this snapshot is taken from the supplied report generated after CTest. The report does not state the tested source revision, OS, compiler, or build configuration; those details remain unrecorded. See the [test report snapshot](../../test-report-status.md) for the wider report scope.


## 7. Development Notes (for maintainer review)

The source contains the comment in `test_bufferio2()` explaining that the case is intended to avoid a null `c_str()` result being passed to output functions (the nearby `std::cout` / `printf` examples are commented out). This is retained as a development note, not treated as a complete API contract or a replacement for dedicated null-handling tests.
