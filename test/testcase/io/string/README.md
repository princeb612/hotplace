## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# String testcases

## 1. What

This testcase group tests URL component splitting through `split_url()`. It checks four HTTPS URLs and compares the resulting scheme, host, port, full URI, path-only component, query, and fragment fields. It is a focused set of examples, not a complete URI parser conformance suite.

## 2. How

### 2.1 Shared helper and call path

1. `testcase_string()` calls `test_string()`. Each of its four blocks calls `do_split_url(url, &url_info)`, which invokes `split_url()`. The helper prints the resulting fields only when verbose mode is enabled; in that same diagnostic block it passes the query to `http_uri::to_keyvalue()` and prints the key/value pairs. The testcase assertions do not compare those key/value pairs.

2. The same `url_info_t` object is reused for each case, so each case's assertions also check whether the parser leaves query/fragment empty when the input has neither.

### 2.2 HTTPS URL with one path segment

1. **Input**

```text
https://test.com/test.txt
```

2. **Procedure**

1. Call `split_url()` through `do_split_url()`.
2. Compare `scheme` with `https` and `host` with `test.com`.
3. Compare `port` with `443`, verifying the default selected for HTTPS when the input omits a port.
4. Compare both `uri` and `uripath` with `/test.txt`.
5. Assert that `query` and `fragment` are empty.

3. **Evidence from assertions:** seven field assertions cover scheme, host, default port, URI, path, query absence, and fragment absence. They do not test percent-encoding or malformed authority syntax.

### 2.3 Nested path without query or fragment

1. **Input**

```text
https://test.com/path/test.txt
```

2. The same seven field comparisons are made, but the expected `uri` and `uripath` are both `/path/test.txt`. This distinguishes the nested-path case from the preceding single-segment case while retaining the implicit HTTPS port and empty query/fragment expectations. It is still one ordinary host/path form, not a test of dot-segment normalization or encoded path delimiters.

### 2.4 Explicit port and query

1. **Input**

```text
https://test.com:8080/path/test.script?no=1&category=xfile
```

2. The testcase asserts scheme `https`, host `test.com`, port `8080`, full URI `/path/test.script?no=1&category=xfile`, path-only value `/path/test.script`, query `no=1&category=xfile`, and an empty fragment.

3. This case checks that the explicit port overrides the default and that the full URI differs from the path-only field when a query is present. It does not assert parsed key/value pairs such as `no → 1` and `category → xfile`; that conversion is printed only in verbose mode.

### 2.5 Explicit port, query, and fragment

1. **Input**

```text
https://test.com:8443/path/test.script?no=1&category=xfile#file
```

2. The testcase asserts scheme `https`, host `test.com`, port `8443`, full URI `/path/test.script?no=1&category=xfile#file`, path-only value `/path/test.script`, query `no=1&category=xfile`, and fragment `file`.

3. This case checks that the fragment is exposed separately while remaining part of the full URI string. The assertions do not establish behavior for empty fragments, multiple delimiters, malformed URLs, user information, IPv6 literals, or percent-encoded reserved characters.

## 3. Evidence

### Source-level coverage

**URL splitting**

```text
URL input (4 selected cases)
  -> do_split_url() -> split_url()
  -> assert scheme
  -> assert host
  -> assert port
  -> assert URI
  -> assert path
  -> assert query
  -> assert fragment
```

The no-port cases assert the default HTTPS port; explicit-port cases assert the supplied port override.

**Query key/value conversion**

```text
query string -> http_uri::to_keyvalue() -> verbose print
  -> no comparison against an expected key/value map
```

The explicit assertions cover these ordinary URL forms only, not malformed authorities, percent encoding, IPv6 literals or every delimiter combination.



The shared [Test Report Snapshot](../../test-report-status.md) reports the aggregate `io` target, not a separate `io/string` result. Do not attribute the parent count to these four URL cases alone. The snapshot is associated with Revision 1104 MinGW64/GCC CTest context; the tested commit and exact compiler/build configuration are not independently encoded in the report files.

Source-level evidence is the seven explicit field assertions per case. Verbose URL and query key/value output is diagnostic only. This documentation change did not run the tests.



## 4. Relationships

- `sdk/io/string/` — implementation-side URL/string helpers.
- [I/O testcase suite](../README.md) — executable dispatch and shared report.
- [`testcase_string.cpp`](testcase_string.cpp) — four URL inputs and assertions.
- [`sample.cpp`](../sample.cpp) and [`CMakeLists.txt`](../CMakeLists.txt) — invocation and target source collection.

## 5. References

- [RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986) — general URI syntax background; these examples do not claim full RFC conformance.
