## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source basis: Revision 1107                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```
# I/O String

## 1. Role

`sdk/io/string` contains text utilities that are directly useful at I/O and protocol boundaries: tokenization, URL escaping/decomposition, and platform-specific character conversion. It is not the same layer as `sdk/base/string`, whose purpose is general string support.

## 2. Data Model

| Source/module | Responsibility | Detail document |
|---|---|---|
| `string.hpp` / `string_charset.cpp` | `tokenize()` and `gettoken()` for narrow strings, plus wide-string variants under Windows/Unicode build conditions | [string.md](string.md) |
| `windows/mbs2wcs.cpp`, `windows/wcs2mbs.cpp` | `A2W()` / `W2A()` conversion using Win32 character conversion APIs | [string.md](string.md) |
| `unicode/string_wcs.cpp` | Unicode-build implementation variant of the shared string helpers | [string.md](string.md) |
| `url.cpp` | percent escaping/unescaping and URL decomposition into `url_info_t` | [url.md](url.md) |

## 3. Behavior Model

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


`tokenize()` advances a caller-owned position through delimiter-separated text; `gettoken()` selects a token by index and is implemented using tokenization. The API is intentionally lightweight and should not be mistaken for a grammar-aware parser.

`split_url()` is also a lightweight decomposition helper, not a complete modern URL-standard implementation. Its output reflects the syntax and default-port behavior implemented in `url.cpp`; callers should not infer full standards conformance from the presence of URL-related fields.

### URL and character conversion boundaries

URL decomposition, percent escaping/unescaping, tokenization, and character conversion are related string utilities but have different contracts. URL tests do not establish the behavior of the platform-specific character-conversion paths; check the relevant implementation selected by the build.

## 4. Relationships
- `sdk/base/string/` — general string helpers; names such as `tokenize`/`gettoken` may look similar, so confirm the namespace and header being used.
- `sdk/base/encoding/base16` — percent-escape hexadecimal representation.
- `sdk/base/pattern/` — regular-expression helper used by URL decomposition.
- `sdk/base/stream/` — stream output target for URL escaping/unescaping.
- `sdk/net/http/` — principal consumer of `url_info_t` and `split_url()`.
- `sdk/crypto/authenticode/` — uses URL decomposition when processing CRL URLs.
- Implementation entry points are `string.hpp`, `string_charset.cpp`, and `url.cpp`, with platform variants under `windows/` and `unicode/`; check these when determining which conversion path a build selects.

## 5. References
- RFC 2396 — URI syntax referenced by the implementation comments.
- RFC 2068 — historical HTTP syntax reference in the source comments.

These references describe historical assumptions recorded in the code; the implementation behavior should be judged from its actual code and tests, not assumed to implement every modern URL/URI requirement.

