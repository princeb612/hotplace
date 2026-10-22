## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# Basic testcases

## 1. What

The basic I/O testcase sources cover OID dictionary lookup, ASN.1 textual OID conversion, payload serialization/parsing, group-controlled fields, inferred field lengths, 24-bit integers, a 48-bit DTLS record sequence number, bignumber conversion, and QUIC variable-length integer encoding. The key purpose of the payload cases is to check field-layout logic against concrete byte strings, not merely to print decoded values.

## 2. How

### 2.1 OID dictionary initialization and lookup

1. **initialize dictionary.** `load_oid()` calls `oid_dictionary::get_instance()` and then records an unconditional `assert(true)`. This is a timing/logging marker: it does not compare dictionary contents or assert a measured loading-time threshold.

2. **dotted-decimal OID lookup.** `test_oid()` looks up `2.16.840.1.101.3.4.2.1` into an `oid_metadata`. It logs name and description if lookup succeeds and asserts that the lookup result is true. The asserted property is successful lookup, not the exact metadata strings.

3. **ASN.1 notation conversion then lookup.** `test_oid2()` converts `{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) hashalgs(2) 3}` using `asn1str_to_oid()`, then looks up the resulting `oid_t` and asserts success. The test does not compare the converted OID object against a separately specified dotted-decimal string; its end-to-end check is that the converted value is known to the dictionary.

### 2.2 Payload field serialization with optional group

1. **write the same schema with the group enabled and disabled.**

2. The schema is ordered as follows:

| Field | Representation | Group |
|---|---|---|
| `padlen` | 1-byte `uint8`, value 3 | `pad` |
| `data` | bytes `data` | always present |
| `value` | big-endian 32-bit `0x1000` | always present |
| `pad` | bytes `pad` | `pad` |

3. With group `pad` enabled, the complete expected byte sequence is `03 64 61 74 61 00 00 10 00 70 61 64`: length, ASCII `data`, 32-bit integer, ASCII `pad`. The test also reads named values back from the in-memory payload and asserts length 3, the `data` bytes, value `0x1000`, and `pad` bytes. With the group disabled, it asserts the complete output `64 61 74 61 00 00 10 00`; the two group members are omitted together.

4. These full-buffer comparisons are the principal oracle. The assertion labels for the in-memory data/value fields are slightly misleading, but the compared values are explicit. The test does not exercise invalid group names or malformed payload input.

### 2.3 Payload parsing with inferred variable field length

1. **infer `data` size from a trailing field.**

2. Input bytes are `03 64 61 74 61 00 00 10 00 70 61 64`. The payload schema declares a one-byte `padlen`, variable `data`, fixed four-byte big-endian `value`, and variable `pad`. `set_reference_value("pad", "padlen")` ties the final `pad` size to the parsed `padlen` value.

3. The parser first learns `padlen = 3`; the fixed-size fields consume one and four bytes, and the referenced trailing field consumes three bytes. From the 12-byte input, `data` therefore occupies (12 - 1 - 4 - 3 = 4) bytes. Assertions compare `padlen` to 3, `data` to ASCII `data`, `value` to `0x1000`, and `pad` to ASCII `pad`. The test then serializes the parsed payload and asserts that the output is byte-for-byte equal to the original input.

4. This proves the selected valid-input inference and round trip; it does not establish safe behavior for inconsistent length references, truncated fields, or trailing garbage.

### 2.4 24-bit integer conversion

1. **helper conversion.** Input bytes `00 03 28` are passed to `b24_i32()`; the resulting integer must equal `0x0328`. The test then converts that integer back to three bytes using `i32_b24()` and compares all three bytes with the original input.

2. **24-bit value inside payload.** The payload contains one-byte `padlen = 3`, a three-byte `uint24_t(0x100000)`, a big-endian 32-bit `0x10000000`, and ASCII `pad`. Serialization is compared against `03 10 00 00 10 00 00 00 70 61 64`. A second payload reads those bytes and checks `padlen = 3` and the 24-bit value `0x100000`, then writes the payload back and compares the complete buffer. Although the 32-bit value is read for diagnostic logging, there is no direct assertion on that decoded 32-bit field in this function.

### 2.5 Conditional groups controlled by a header

1. **header enables group 2.** Input `01 00 05 64 61 74 61 31 00 05 64 61 74 61 32` begins with header byte 1, then a two-byte length and `data1`, followed by a second two-byte length and `data2`. A condition callback reads the header and enables `group2` when it is nonzero. Reference rules use `len1` and `len2` to determine the two byte-string lengths. The function asserts that the resulting group condition equals the expected `true`.

2. **header disables group 2.** Input `00 00 05 64 61 74 61 31` uses header byte 0 and contains only the first group. The same callback disables `group2`; the function asserts the condition is `false`. It also serializes selected group combinations for diagnostics, but does not compare those serialized buffers with fixed expected vectors. The assertions validate the condition switch, not every decoded field or emitted byte.

### 2.6 DTLS record header with a 48-bit sequence number

1. **parse a captured record prefix.** The testcase feeds a fixed hexadecimal capture beginning with a DTLS handshake record into a payload schema containing content type, record version, and length, plus an optional `dtls` group with epoch and a 48-bit sequence number. A callback inspects the record version through `tls_advisor` and enables the group when the version is recognized as DTLS.

2. The explicit assertions expect handshake content type, DTLS 1.2 version, epoch 0, record sequence number 1, and record length `0x61`. This demonstrates version-driven field selection and extraction from this selected capture. It does not validate the entire record body, certificate contents, record authentication, or general TLS-versus-DTLS record parsing.

### 2.7 Bignumber payload round trip

1. **serialize and reconstruct a 256-bit maximum signed value.** The source computes ((1 ll 255) - 1), writes it after a big-endian 32-bit length field set to 32 bytes, then parses the result using a payload whose `bn` field length references `bnlen`. It obtains the decoded bytes, constructs a new `bignumber`, and asserts equality with the original value. The hexadecimal dump and decimal/hex strings are diagnostic; the equality comparison is the actual oracle. This single positive value does not cover negative values, zero, arbitrary length prefixes, or overflow handling.

### 2.8 QUIC variable-length integer and opaque data

1. The companion `testcase_payload_quic.cpp` has two testcase functions.

2. **variable-length data members.** `test_quic_integer()` builds two text segments with declared lengths 59 and 37, using `quic_encoded` and payload members. The expected byte string is the RFC 9000 Appendix A.1 encoding of those lengths followed by the ASCII text. The first path writes values and text and compares the complete buffer. The second path declares length fields initially as zero, binds each data field's length to its preceding encoded integer with `set_reference_value()`, reads the first buffer, writes it back, compares the complete bytes, and asserts that the decoded length values are 59 and 37. Additional paths encode text directly through `quic_encoded`, decode and re-encode it, and assert a one-byte `00` representation for an empty value. An opaque-data case reads `05 01 02 03 04 05`, then asserts the decoded length is 5 and the data bytes equal `01 02 03 04 05`.

3. **integer known-answer vectors.** `test_quic_encoded()` applies a helper to each value: encode it, compare with the expected hexadecimal bytes, decode into a new `quic_encoded`, re-encode, and compare again. Vectors cover RFC 9000 Appendix A.1 values and the boundaries around the 1-, 2-, 4-, and 8-byte encoding lengths: `0x00`, `0x3f`, `0x40`, `0x3fff`, `0x4000`, `0x3fffffff`, `0x40000000`, and `0x3fffffffffffffff`. These are known-answer and round-trip checks for valid encodings; malformed encodings, forbidden values, and truncated inputs are not covered here.

## 3. Evidence

### Source-level coverage

**1. OID conversion and lookup**

```text
OID text / ASN.1 OID form -> parse or convert -> advisor dictionary lookup
  -> compare selected resolved OID/name
```

**2. Payload serialization and parsing**

```text
payload schema + field values
  -> serialize fields in declared order
  -> compare complete output bytes == expected buffer

fixed-length / referenced-length payload bytes
  -> parse length and field boundaries
  -> compare decoded length, data, value and padding
  -> serialize parsed representation
  -> compare output bytes where explicitly asserted
```

**3. Conditional fields and DTLS layout**

```text
header flags / presence conditions -> serialize selected fields
  -> compare expected bytes and decoded field values
DTLS header -> selected sequence-number layout -> compare expected representation
```

**4. Bignumber and QUIC varint**

```text
selected large integer -> payload binary form -> compare selected bytes/value
QUIC integer -> encode -> compare known-answer bytes -> decode -> compare value
```

These cases do not exhaust every integer boundary, malformed encoding or optional-field combination.



The shared [Test Report Snapshot](../../test-report-status.md) contains the aggregate `io` result only; it has no separate `io/basic` or per-function row. Do not attribute the aggregate count to these cases individually. The last supplied run association is Revision 1104 · MinGW64/GCC · CTest; report files do not independently identify the tested commit or complete build configuration. This documentation update did not execute tests.



## 4. Relationships

- `sdk/io/basic/` — implementation-side OID and payload facilities.
- [I/O testcase suite](../README.md) — dispatch and aggregate report context.
- [`CMakeLists.txt`](../CMakeLists.txt) — source collection and YAML copy rules.
- [`testcase_oid.cpp`](testcase_oid.cpp) — dictionary initialization and OID lookups.
- [`testcase_payload.cpp`](testcase_payload.cpp) — payload, length references, groups, integer widths, DTLS header, and bignumber.
- [`testcase_payload_quic.cpp`](testcase_payload_quic.cpp) — QUIC varint and opaque data cases.

## 5. References

- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000), Appendix A.1 — known-answer values and encoding boundaries used by the QUIC tests.
