## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
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

The `url_info_t` fields and default-port values describe the result contract. The order in which the implementation unescapes and splits the input is part of the execution path described under Behavior Model.

### Percent escaping

`escape_url()` writes output to a `stream_t`; `unescape_url()` decodes percent-escaped byte pairs into a stream. Escaped bytes use uppercase hexadecimal digits through the base16 helper. The current allowlist includes alphanumeric characters, RFC 2396 reserved/mark characters, and the source's `delims` set (`<>#%\"`); those delimiter characters are therefore emitted unchanged despite the comment labelling them excluded. `unescape_url()` does not validate malformed escapes: a lone trailing `%` is skipped; if only one character follows `%`, the current size check still attempts a two-character decode using the terminating NUL as the second character. The return status from decoding a pair is ignored.

## 3. Behavior Model

### Conversion behavior

```text
text ──escape_url──> percent-escaped bytes
text ─unescape_url─> decoded bytes
raw URL ──unescape_url──> decoded text ──regex_token──> url_info_t fields
```

`split_url()` first calls `unescape_url()` on the entire input and then applies separate regular expressions for authority, path, query, and fragment. Percent-encoded delimiters can therefore become structural characters before decomposition. The authority pattern requires an initial lowercase letter before `://` and restricts the authority to a narrow character set; path, query, and fragment each have their own restricted character classes. The default ports supplied by the implementation are HTTP 80, HTTPS 443, and FTP 21. A non-null call retains its initial success status even when the expressions do not populate meaningful fields, so empty fields are not a validation error. The output is intended for the specific URL forms consumed by this codebase; it does not normalize every URI form or validate current URL standards. Preserve the distinction between `uri` and `uripath`: the testcase expects `uri` to retain query and fragment text while `uripath` contains only the path.

### Source-level evidence
`test/testcase/io/string/testcase_string.cpp` calls `split_url()` on several concrete strings and asserts the fields. For example, for `https://test.com:8443/path/test.script?no=1&category=xfile#file`, it checks `scheme == "https"`, `host == "test.com"`, `port == 8443`, `uripath == "/path/test.script"`, `query == "no=1&category=xfile"`, and `fragment == "file"`. The testcase does not call `escape_url()` or `unescape_url()` directly; their behavior above is derived from the implementation source, not a dedicated test assertion.

The same test also covers an HTTPS URL without an explicit port (expected default `443`), a URL with a query but no fragment, and a path with no query. This is direct evidence for the fields asserted, not a claim of exhaustive URL conformance.

The HTTP layer consumes `url_info_t` for URI/request handling, and Authenticode CRL handling also uses `split_url()`.

### Concrete consumer path: HTTP request URL

The HTTP client uses `split_url()` to turn a URL string into the connection/request fields. The parsed host and port are used for the request's Host header (formatted as `host:port`), while `uri` becomes the HTTP request target:

```cpp
#include <hotplace/sdk/io/string/string.hpp>

// Reduced from sdk/net/http/http_client.cpp
url_info_t url_info;
split_url(url.c_str(), &url_info);

request.get_http_header().add(
    "Host",
    basic_stream("%s:%i", url_info.host.c_str(), url_info.port).c_str());
request.compose(http_method_t::HTTP_GET, url_info.uri, "");
```

This shows why the result retains both `uri` and `uripath`: the HTTP request target needs the URI form, including query text where present, while other consumers may need only the path. `split_url()` decomposes the input; it does not itself perform DNS resolution, establish a connection, or validate every URI rule.

Source: `sdk/net/http/http_client.cpp`, `http_client::request(const std::string&, http_response**)`.

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
- [RFC 2396 — Uniform Resource Identifiers (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc2396) — historical URI syntax referenced by implementation comments.
- [RFC 2068 — Hypertext Transfer Protocol — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc2068) — historical HTTP syntax reference in source comments.
