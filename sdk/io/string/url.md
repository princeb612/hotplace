## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# URL Utilities

## 1. Role

`url.cpp` implements URL-oriented helpers in `sdk/io/string`: percent escaping/unescaping and decomposition of URL text into `url_info_t`. It is a lightweight utility for the project's protocol code, not a full URL parser with comprehensive standards validation.

## 2. Data Model
### `url_info_t` and `split_url()`

`url_info_t` carries the fields consumed by higher-level code:

- `scheme` — scheme such as `http` or `https`
- `host` — host text
- `port` — explicit port or a default supplied by the implementation
- `uri` — URI portion retained by the helper, including query/fragment text where present
- `uripath` — path portion
- `query` — query text without the leading `?`
- `fragment` — fragment text without the leading `#`

The implementation first unescapes the input and then uses the project's regex helper to identify components. The source currently supplies default ports for `http` (80), `https` (443), and `ftp` (21) when the port is omitted.

### Percent escaping

`escape_url()` writes escaped output to a `stream_t`; `unescape_url()` decodes percent-escaped byte pairs into a stream. Escaped bytes are represented with hexadecimal digits through the base16 helper.

```text
text ──escape_url──> percent-escaped bytes
text ─unescape_url─> decoded bytes
URL  ──split_url───> url_info_t fields
```

## 3. Behavior Model
The output is intended for the specific URL forms consumed by this codebase. The function does not claim to normalize every URI form or validate every rule of current URL standards. In particular, preserve this distinction when documenting `uri` versus `uripath`: the testcase expects `uri` to retain query/fragment text while `uripath` contains only the path.

### Source-level evidence
`test/testcase/io/string/testcase_string.cpp` calls `split_url()` on several concrete strings and asserts the fields. For example, for `https://test.com:8443/path/test.script?no=1&category=xfile#file`, it checks `scheme == "https"`, `host == "test.com"`, `port == 8443`, `uripath == "/path/test.script"`, `query == "no=1&category=xfile"`, and `fragment == "file"`.

The same test also covers an HTTPS URL without an explicit port (expected default `443`), a URL with a query but no fragment, and a path with no query. This is direct evidence for the fields asserted, not a claim of exhaustive URL conformance.

The HTTP layer consumes `url_info_t` for URI/request handling, and Authenticode CRL handling also uses `split_url()`.

## 4. Relationships
- `sdk/base/encoding/base16` — hexadecimal representation used by percent escaping.
- `sdk/base/pattern/` — regular-expression matching used by URL decomposition.
- `sdk/base/stream/` — output target for escaped/unescaped text.
- `sdk/net/http/` — principal consumer of URL decomposition.
- `sdk/crypto/authenticode/` — CRL URL consumer.

### Implementation source navigation
- `sdk/io/string/url.cpp`
- `sdk/io/string/string.hpp`
- `test/testcase/io/string/testcase_string.cpp`

## 5. References
- RFC 2396 — URI syntax referenced by implementation comments.
- RFC 2068 — historical HTTP syntax reference in implementation comments.

These are historical source references. They should not be presented as evidence that the implementation fully conforms to either document or to later URL/URI standards.
