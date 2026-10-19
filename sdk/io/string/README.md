## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# I/O String

## 1. Role

`sdk/io/string` contains text utilities that are directly useful at I/O and protocol boundaries: tokenization, URL escaping/decomposition, and platform-specific character conversion. It is not the same layer as `sdk/base/string`, whose purpose is general string support.

## 2. Model

| Source/module | Responsibility | Detail document |
|---|---|---|
| `string.hpp` / `string_charset.cpp` | `tokenize()` and `gettoken()` for narrow strings, plus wide-string variants under Windows/Unicode build conditions | [string.md](string.md) |
| `windows/mbs2wcs.cpp`, `windows/wcs2mbs.cpp` | `A2W()` / `W2A()` conversion using Win32 character conversion APIs | [string.md](string.md) |
| `unicode/string_wcs.cpp` | Unicode-build implementation variant of the shared string helpers | [string.md](string.md) |
| `url.cpp` | percent escaping/unescaping and URL decomposition into `url_info_t` | [url.md](url.md) |

### URL decomposition path

```text
URL text
  │
  ▼
split_url()
  ├── scheme / host / port
  ├── uri / uripath
  ├── query
  └── fragment
       │
       ▼
HTTP URI/request handling and other URL consumers
```

## 3. Important behavior and lifetime

`tokenize()` advances a caller-owned position through delimiter-separated text; `gettoken()` selects a token by index and is implemented using tokenization. The API is intentionally lightweight and should not be mistaken for a grammar-aware parser.

`split_url()` is also a lightweight decomposition helper, not a complete modern URL-standard implementation. Its output reflects the syntax and default-port behavior implemented in `url.cpp`; callers should not infer full standards conformance from the presence of URL-related fields.

## 4. Example from the source tests

The direct test is `test/testcase/io/string/testcase_string.cpp`. Its `test_string()` function calls `split_url()` for several inputs and checks `scheme`, `host`, `port`, `uri`, `uripath`, `query`, and `fragment`. The cases cover an HTTPS URL with the default port, a path with multiple components, an explicit port and query string, and a fragment.

For a traceable example, start with `https://test.com:8443/path/test.script?no=1&category=xfile#file`: the test expects scheme `https`, host `test.com`, port `8443`, path `/path/test.script`, query `no=1&category=xfile`, and fragment `file`. This is an executable description of the output contract rather than a link-only pointer.

The Windows `A2W()` / `W2A()` variants are platform-specific and should be reviewed with their corresponding source files; the URL test does not by itself validate character-conversion behavior.

## 5. Relationships

- `sdk/base/string/` — general string helpers; names such as `tokenize`/`gettoken` may look similar, so confirm the namespace and header being used.
- `sdk/base/encoding/base16` — percent-escape hexadecimal representation.
- `sdk/base/pattern/` — regular-expression helper used by URL decomposition.
- `sdk/base/stream/` — stream output target for URL escaping/unescaping.
- `sdk/net/http/` — principal consumer of `url_info_t` and `split_url()`.
- `sdk/crypto/authenticode/` — uses URL decomposition when processing CRL URLs.

## 6. References

- RFC 2396 — URI syntax referenced by the implementation comments.
- RFC 2068 — historical HTTP syntax reference in the source comments.

These references describe historical assumptions recorded in the code; the implementation behavior should be judged from its actual code and tests, not assumed to implement every modern URL/URI requirement.

### Source

- `sdk/io/string/string.hpp`
- `sdk/io/string/string_charset.cpp`
- `sdk/io/string/url.cpp`
- `sdk/io/string/windows/`
- `sdk/io/string/unicode/`
