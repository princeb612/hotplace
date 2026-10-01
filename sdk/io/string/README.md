# I/O String

`sdk/io/string` contains string utilities used at the boundary between textual data and I/O/protocol processing.

It is intentionally different from `sdk/base/string`: the base layer provides general string facilities, while this directory contains utilities whose behavior is tied to I/O-facing representations, URL syntax, character-set/platform conversion, and simple tokenization used by protocol code.

## Implementation map

| Module | Role |
|---|---|
| `string.hpp` / `string_charset.cpp` | `tokenize`, `gettoken`, and platform/character-set variants |
| `url.cpp` | URL percent-escape/unescape and URL decomposition |
| `windows/` | Windows multibyte/wide-character conversion (`A2W`, `W2A`) |
| `unicode/` | Unicode build variant of the string implementation |

## Documents

- [string](string.md) — tokenization and character-set/platform handling
- [url](url.md) — URL escaping, unescaping, and decomposition

## Related areas

- `sdk/base/string/` — general string utilities
- `sdk/base/encoding/` — Base16 used by URL percent encoding
- `sdk/base/pattern/` — regex used by `split_url`
- `sdk/base/stream/` — output stream used by URL encode/decode
- `sdk/net/http/` — HTTP URI/request handling built on `url_info_t` and `split_url`
- `sdk/crypto/authenticode/` — CRL URL handling uses `split_url`

## Related tests

There is no dedicated `test/testcase/io/string/` directory. The implementation is exercised through users of the facility, especially:

- `test/testcase/net/http/testcase_http.cpp`
- `test/testcase/base/string/testcase_string.cpp` for the similarly named but separate base-layer string utilities

## Source

- `sdk/io/string/string.hpp`
- `sdk/io/string/string_charset.cpp`
- `sdk/io/string/url.cpp`
- `sdk/io/string/windows/`
- `sdk/io/string/unicode/`
