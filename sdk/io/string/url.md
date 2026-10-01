# URL Utilities

`url.cpp` provides the URL-oriented portion of `sdk/io/string`. It is a small protocol-facing utility rather than a complete URL parser.

## Percent escaping

`escape_url()` writes a percent-encoded representation to a `stream_t`.

The implementation classifies characters using the URI character categories documented in the source and uses the base16 encoder to emit escaped bytes. `unescape_url()` performs the reverse operation by decoding two hexadecimal characters following `%`.

The implementation is intentionally stream-oriented:

```text
URL text
  ↓
escape_url / unescape_url
  ↓
stream_t
```

## URL decomposition

`split_url()` fills `url_info_t` with the fields needed by HTTP-oriented code:

- `scheme`
- `host`
- `port`
- `uri`
- `uripath`
- `query`
- `fragment`

The function first unescapes the input, then uses the base regex facility to identify the scheme/host/port and path/query/fragment portions. Default ports are supplied for `http` (80), `https` (443), and `ftp` (21) when no explicit port is present.

This is therefore best understood as a lightweight URL/URI decomposition helper for the project's protocol code, not as a general standards-complete URL implementation.

## Actual usage

The HTTP testcase verifies:

- HTTPS scheme/host/default port extraction
- path/query/fragment extraction
- percent-encoded redirect URI handling
- relative URI query extraction
- `unescape_url()` behavior

`http_uri`, `http_client`, and HTTP request handling use `split_url()` to turn request/URI text into the fields needed by higher-level HTTP code.

The Authenticode verifier also uses `split_url()` when processing CRL URLs, so this small utility is shared beyond HTTP.

## Related areas

- `sdk/base/encoding/base16` — hexadecimal encoding/decoding used for `%XX`
- `sdk/base/pattern/regex` — URL component matching
- `sdk/base/stream` — stream output target
- `sdk/net/http/` — primary protocol consumer
- `sdk/crypto/authenticode/` — CRL URL consumer

## Related tests

- `test/testcase/net/http/testcase_http.cpp`

Representative cases include:

- `https://test.com/resource?client_id=12345#part1`
- percent-encoded `redirect_uri`
- `/client/cb?code=...&state=xyz`
- `https://test.com:8080/%7Eb612%2Ftest%2Ehtml`

## Related references

The implementation comments refer to the URI syntax described by RFC 2396 and RFC 2068. These references explain the historical syntax assumptions in the code; the implementation should be treated according to its actual supported behavior rather than as a claim of full modern URI standard coverage.

## Source

- `sdk/io/string/url.cpp`
- `sdk/io/string/string.hpp`
