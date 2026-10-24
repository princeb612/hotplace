## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base64

## 1. Role

### Introduction

`base64` implements RFC 4648 Base64 and Base64URL encoding and decoding. The caller selects the representation through `encoding_t`; the two forms are not interchangeable text strings.

## 2. Data Model

### Representations

| Variant | Alphabet / padding convention |
|---|---|
| Base64 | Uses `+` and `/`; ordinary Base64 padding rules apply. |
| Base64URL | Uses `-` and `_`; the URL-oriented API uses the unpadded representation. |

The API accepts raw byte ranges and common hotplace containers. The low-level routines under `lowlevel/base64.*` implement the conversion; public overloads provide string/byte-vector results and `encoder_stream_traits` output-buffer integration.

### Streaming units

`encoder_stream` and `decoder_stream` retain the incomplete suffix across `write()` calls.

## 3. Behavior Model

### One-shot conversion

Base64 encoding consumes three input bytes per complete group and emits four encoded characters. Decoding consumes four encoded characters per complete group and emits up to three bytes.

The caller selects Base64 or Base64URL and supplies a byte range. The conversion routine applies that variant's alphabet and representation conventions. For templated output-buffer overloads, the wrapper first requests the required capacity from the low-level routine, reserves output storage, performs the conversion, and commits the written length on success. Unless `encoding_notrunc` is set, the destination is truncated before processing.

### Concrete caller path: one-shot round trip

The testcase exercises both convenience-returning overloads and caller-provided output buffers. The latter make status handling explicit:

```cpp
std::string encoded;
std::string decoded;

return_t ret = base64_encode(
    reinterpret_cast<const byte_t*>(sample1), strlen(sample1), encoded);
if (errorcode_t::success == ret) {
    ret = base64_decode(encoded, decoded);
}

_test_case.test(ret, __FUNCTION__, "encode/decode");
_test_case.assert(decoded == sample1, __FUNCTION__, "Base64 round trip");
```

This path uses a textual sample, so comparing the decoded string is appropriate. For arbitrary binary payloads, compare a byte container and preserve the explicit input length; a C-string overload cannot represent embedded zero bytes as part of its inferred length. The actual testcase has separate cases for `binary_t` and `basic_stream`, in addition to this string-oriented path.

Source: `test/testcase/encode/testcase_base64.cpp`.

### Stateful stream flow

```text
encoder_stream::write(chunk)
      │
      ├── complete pending 3-byte group, if possible
      ├── encode remaining complete 3-byte groups
      └── retain 0–2 trailing input bytes
                    │
              str() / flush()
                    └── encode pending tail

decoder_stream::write(chunk)
      │
      ├── complete pending 4-character group, if possible
      ├── decode remaining complete groups
      └── retain incomplete suffix
                    │
             data() / flush()
                    └── process final suffix
```

Chunk boundaries therefore do not have to align with Base64 groups. Finalization is still important: the decoder's current implementation discards a one-character retained suffix, while other non-empty suffixes are passed to the Base64 decoder. Callers should check `write()` status and not assume that every arbitrary trailing fragment is valid.

### Multiline Base64

`base64_encode_multiline()` uses an `encoder_stream` to encode the payload, then inserts line breaks at the requested column width; zero disables wrapping. `base64_decode_multiline()` scans line breaks, trims surrounding whitespace on each line, and feeds line content into a `decoder_stream`. This is a text-wrapping helper, not a different Base64 alphabet.

### Relation to Radix-64

Radix-64 reuses Base64 for its payload and adds CRC-24 checksum processing.

## 5. Relationships

- `lowlevel/base64.*` provides byte-level conversion used by public overloads.
- `encoder_stream` and `decoder_stream` preserve incomplete units across chunk boundaries.
- `radix64.*` composes Base64 with CRC-24 and armor-oriented processing.
- `test/testcase/encode/testcase_base64.cpp` provides source-level coverage for ordinary Base64, Base64URL, chunked streaming, multiline processing, and RFC 4880 Radix-64 vectors/armor examples.

## 6. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [RFC 7515 — JSON Web Signature (JWS), Appendix C](https://www.rfc-editor.org/rfc/rfc7515)
