## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# OID Conversion

## 1. Role

`sdk/io/basic/oid.*` converts object-identifier notation between dotted decimal text and a vector of integer nodes. It also provides `asn1str_to_oid()` for extracting numeric nodes from the brace-and-label form used in ASN.1 descriptions. The adjacent `oid_dictionary` uses this representation for lookup.

```text
"2.16.840.1.101.3.4.2.1" ──str_to_oid──> [2,16,840,1,101,3,4,2,1]
ASN.1 braced notation ─────asn1str_to_oid─> node vector ──> oid_dictionary lookup
node vector ────────────────oid_to_str─────> dotted decimal text
```

## 2. Model

`oid_t` is an alias for `std::vector<uint32>`. The API is deliberately small:

- `str_to_oid(const std::string&, oid_t&)` delegates to the buffer-and-size overload.
- `str_to_oid(const char*, size_t, oid_t&)` scans dotted decimal tokens and converts each token to a 32-bit node.
- `asn1str_to_oid(const char*, size_t, oid_t&)` extracts digit sequences from ASN.1-style text using the project's regex-token helper.
- `oid_to_str(const oid_t&, basic_stream&)` writes nodes separated by `.` into a stream.

The code is a representation/conversion layer, not a complete OID validator. In particular, callers should not infer that the helper alone enforces all first-node/second-node constraints or performs BER/DER base-128 encoding.

## 3. Important behavior and lifetime

`str_to_oid()` clears the output vector before scanning, and `asn1str_to_oid()` also clears its output before extracting numeric tokens. `oid_to_str()` clears the destination stream before writing the dotted representation. This means these functions replace the output rather than append to prior contents.

The ASN.1-braced parser is intentionally lexical: it extracts decimal runs. The caller is responsible for supplying the expected notation and for interpreting the result in the proper ASN.1 context. BER/DER OBJECT IDENTIFIER byte encoding is implemented by `sdk/io/asn.1/`, not here.

## 4. Example from the source tests

`test/testcase/io/basic/testcase_oid.cpp` demonstrates the conversion in its actual use context:

1. `load_oid()` initializes the singleton dictionary.
2. `test_oid()` looks up the dotted string `2.16.840.1.101.3.4.2.1`; a successful lookup logs the resolved name and description.
3. `test_oid2()` passes ASN.1-braced text such as `{joint-iso-itu-t(2) country(16) us(840) ... hashalgs(2) 3}` to `asn1str_to_oid()`, then looks up the resulting node vector.

The test confirms dictionary lookup through both accepted input forms. It does not directly assert a `str_to_oid()` → `oid_to_str()` round trip, so the documentation does not claim that this testcase covers that behavior.

## 5. Relationships

- `oid_dictionary.hpp/.cpp` — uses `str_to_oid()` to index and search the OID trie.
- `sdk/io/asn.1/basic/` — uses the conversion helpers as part of ASN.1 value encoding/decoding; BER/DER rules live there.
- `sdk/base/nostd/atoi.hpp` and `sdk/base/string/string.hpp` — numeric token conversion and scanning helpers used by this implementation.
- `sdk/base/stream/basic_stream.hpp` — output target for `oid_to_str()`.

## 6. References

- ITU-T X.660 / ISO/IEC 9834-1 — object identifier framework.
- ISO/IEC 6523 — identification of organizations and organization parts, referenced in the source header.

### Related source

- `sdk/io/basic/oid.hpp/.cpp`
- `sdk/io/basic/oid_dictionary.hpp/.cpp`
- `test/testcase/io/basic/testcase_oid.cpp`
