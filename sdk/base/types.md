## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Shared base types

## 1. Role

`types.hpp` is the common type and platform-header foundation for `sdk/base`. It imports OS-specific definitions, declares shared byte/value aliases, and defines common enums and helpers used by the rest of the SDK.

## 2. Data Model

- `byte_t` is the unsigned byte type; `binary_t` derives from `std::vector<byte_t>` and inherits its constructors and assignment operators.
- `loglevel_t` provides ordered logging levels.
- `encoding_t` identifies encoding families such as Base16, RFC-style Base16, Base64, Base64URL, and HTTP/2 Huffman.
- The header also centralizes common integer, container, and platform-related definitions used by other base headers.

The Linux and Windows branches include their corresponding platform type headers and OS/network headers. Consequently, including this file can bring platform declarations into a translation unit; it is not a minimal, platform-neutral type-only header.

## 3. Behavior Model

`loglevel_helper` converts numeric or textual values to levels and levels back to uppercase names. The string path normalizes input and handles recognized aliases; unknown values use the documented default/`UNKNOWN` behavior.

**Binary representation**

`binary_t` provides vector-like byte storage. Its equality operator compares size and then byte content. It does not define the byte order or wire encoding of the stored values; those are chosen by the conversion/encoding API.

**Log-level conversion**

`loglevel_helper::to_loglevel(int)` maps recognized numeric values and falls back to the default level for unknown numbers. The string overload lowercases the input, treats `warning` as `warn`, and falls back to the default for unrecognized strings. `to_string()` returns the uppercase label or `UNKNOWN`.

**Encoding identifiers**

`encoding_t` is an identifier set, not an encoder implementation. The matching encoder/decoder code defines the actual accepted syntax and error behavior.

### Concrete caller path: byte storage and log-level parsing

The shared aliases are used directly in ordinary SDK code:

```cpp
binary_t payload;
payload.push_back(0x16);
payload.push_back(0x03);
payload.push_back(0x03);

loglevel_t level = loglevel_helper::to_loglevel("debug");
```

`binary_t` is a byte vector, so its contents represent an explicit sequence of octets rather than a C string. `loglevel_helper::to_loglevel()` accepts the textual configuration value and maps recognized names to the corresponding enum; an unrecognized or null name falls back to `default_loglevel`. These two utilities share the base type layer but solve independent problems.

The log-level conversion is also used when interpreting command-line or configuration options; the helper is a mapping function, not a logger configuration operation by itself.

## 4. Relationships

- `sdk/base/error.hpp` — return codes and platform error normalization.
- `sdk/base/encoding/` — consumes `binary_t` and encoding identifiers.
- `sdk/base/stream/` — byte/text stream utilities.
- `sdk/base/system/linux/types.hpp` and `sdk/base/system/windows/types.hpp` — platform-specific type definitions.

## 5. References

No external references are listed.
