## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# Encoding testcase suite

## 1. What

The `encode` target verifies the encoding and decoding facilities used by `sdk/base/encoding`: Base16 and RFC-style hexadecimal input, Base64 and Base64URL, Base128 integer representations, generic Huffman coding, HTTP/2 Huffman coding, and incremental encoder/decoder streams. The suite also covers protocol-specific examples for OpenPGP Radix-64 armor and the RFC 7541 Huffman code table.

The suite mixes several kinds of evidence. Fixed known-answer vectors compare an output with an expected byte or text sequence; round-trip tests compare decoded data with the original input; streaming tests vary the write chunk size; and protocol examples assert selected fields or decoded message bytes. These are distinct properties and should not be described collectively as exhaustive validation of every malformed input or boundary.

| Source | Main test functions | Coverage represented in source |
|---|---|---|
| `testcase_base16.cpp` | `test_base16()`, `test_base16_stream()`, `test_base16_oddsize()`, `test_base16_rfc()` | String/binary/stream overloads, chunked conversion, a 66-byte decoded vector, RFC-style input separators and prefixes, and invalid RFC-style values |
| `testcase_base64.cpp` | `test_base64()`, `test_base64_stream()`, `test_base64_multiline()`, `test_rfc4880_6_5()`, `test_rfc4880_6_6()` | Base64/Base64URL conversion, stream chunk sizes, multiline whitespace and wrapping, RFC 4880 Radix-64/CRC vectors, and ASCII-armored message extraction |
| `testcase_base128.cpp` | `test_base128()`, `test_base128_big()` | Known-answer integer vectors, input-position consumption, byte-array overloads, and `bignumber` round trips including 256-bit values |
| `testcase_huffman.cpp` | `test_huffman()`, `test_huffman_stream()` | Learned and imported Huffman tables, selected symbol codes, encode/decode behavior, RFC 7541 Appendix B codes, and HTTP/2 Huffman stream chunking |
| `sample.cpp`, `sample.hpp` | `main()`, `whatsthis()` | Shared test setup, explicit testcase dispatch, report output, and an optional command-line encoding/decoding utility |

## 2. How

### 2.1 Entry point and execution flow

1. `sample.cpp::main()` configures the shared command-line options and logger, then invokes the testcase functions in this order:

1. `testcase_base16()`
2. `testcase_base64()`
3. `testcase_huffman()`
4. `testcase_base128()`

2. It flushes the logger, emits the testcase report, and then calls `whatsthis()`. The command-line utility in `whatsthis()` is separate from the testcase assertions: options such as `-b16`, `-b64`, `-b64u`, `-p`, and `-rfc` select a conversion and print its result. `-out` can write the resulting bytes to a file. Seeing diagnostic output from that utility is not, by itself, a test assertion.

3. The directory CMake file collects the source files into the `test-encode` executable. The executable's explicit calls above determine which testcase functions are invoked; source inclusion and runtime execution are not interchangeable claims.

### 2.2 Base16 conversion and RFC-style hexadecimal input

1. In `test_base16()`, the test uses two text inputs: an ordinary English sentence and a string containing digits, letters, punctuation, quotes, slashes and other printable characters. Each is encoded and decoded, then compared with a separately constructed `binary_t` containing the original bytes.

2. The same sentence is exercised through output parameters of different types: `std::string`, `binary_t`, and `basic_stream`. The tests check operation status for the status-returning overloads and compare the decoded value with the original representation. This establishes agreement among these selected interfaces; it does not test arbitrary binary values through every overload.

3. `test_base16_stream()` constructs 256 bytes containing values 0 through 255. It feeds the encoder and decoder in pseudo-random chunks of 1–16 bytes, then compares the decoded bytes with the source. This checks that the stream interfaces preserve the selected byte sequence across varying write boundaries. Because chunk lengths are chosen with `std::rand()`, the exact partition is not a fixed known-answer vector.

4. `test_base16_oddsize()` decodes a fixed hexadecimal string and asserts that the result has 66 bytes. It checks the expected decoded length for this particular input; the test does not compare all 66 bytes with a separate expected vector.

5. `test_base16_rfc()` exercises the RFC-style parser/formatter helpers with several input forms:

- a bracketed decimal-byte list;
- colon-separated hexadecimal bytes;
- whitespace-separated hexadecimal tokens;
- an optional `0x` prefix and mixed tabs/newlines;
- an odd-length initial hexadecimal token;
- empty tokens in separated input;
- out-of-range decimal and hexadecimal tokens.

6. For valid forms, the test compares decoded bytes with a canonical expected hexadecimal value. For the two explicitly invalid values, it asserts that the decoded result is empty. The cases named “bad case” that contain empty tokens are not expected to fail: they assert the implementation's current skip/normalization behavior. This is a defined behavior of these test inputs, not proof that every malformed input is rejected consistently.

### 2.3 Base64 and Base64URL conversion

1. `test_base64()` follows the same multi-representation approach as Base16. It uses the English sentence and printable punctuation sample, performs encode/decode round trips, checks status-returning overloads, and compares the decoded data with the original `binary_t`, string or stream value.

2. `test_base64_stream()` runs the shared stream test for both `encoding_base64` and `encoding_base64url`. Each run builds a 256-byte input containing all byte values from 0 through 255. For encoder chunk sizes 1 through 16, it compares the stream encoder's text with the non-stream encoder's output. For decoder chunk sizes 1 through 16, it decodes a canonical encoded string and compares the result with the original 256 bytes. These checks specifically exercise how input chunk boundaries interact with the streaming state; the expected encoded form is generated by the same library's non-stream encoder, so this is not an independent implementation interoperability test.

### 2.4 Multiline Base64 formatting and boundaries

1. `test_base64_multiline()` uses a fixed sentence and checks the exact Base64 text for 80-column formatting and for no wrapping (`column == 0`). It decodes the wrapped form and checks the original bytes. Separate inputs add leading/trailing spaces, LF, CRLF, and tabs around the encoded text; each decoded result is compared with the same original byte sequence.

2. The boundary subtest encodes a 256-byte sequence containing every byte value and examines the lengths of the lines separated by LF. For columns 3, 4, 30, 60, 100, 150 and 344, it derives the expected line-length sequence from the formatted output length and compares that vector with the observed line lengths. This checks the line-wrapping layout for these selected widths; it does not assert a separately fixed full encoded string for each boundary width.

### 2.5 RFC 4880 Radix-64 and ASCII armor

1. `test_rfc4880_6_5()` uses the byte vector `14 FB 9C 03 D9 7E` with lengths 6, 5 and 4. For each length, it calls `radix64_armor_encode()` and compares both the encoded Radix-64 text and the CRC value with fixed expected strings. It then decodes the result with `radix64_armor_decode()`, checks the operation status, and compares the recovered bytes with the corresponding input prefix. This is the suite's direct known-answer check for the selected RFC 4880 Radix-64 and CRC examples.

2. `test_rfc4880_6_6()` parses a sample ASCII-armored PGP message line by line. It begins collecting payload after the empty header separator, treats the line prefixed with `=` as the CRC, and stops collecting the payload there. It asserts the extracted Base64 cleartext and CRC strings, decodes them through `radix64_armor_decode()`, and compares the output with a fixed expected byte sequence.

3. This is a targeted example of the provided armor layout. The line-scanning logic is implemented inside the testcase itself, and these assertions do not establish general parsing correctness for every armor header, malformed message, or line-ending variation.

### 2.6 Base128 integer encoding

1. `test_base128()` compares the encoded bytes against fixed hexadecimal vectors for values 0, 127, 128, 255, 16383 and 16384. For each value, it tests the integer overload and checks the decoded integer and final input position. It also converts the value to a network-byte-order 64-bit buffer, encodes that buffer, decodes to `binary_t`, constructs a `bignumber`, and converts it back to `uint64`. The expected encoded bytes and the final consumed position are checked separately.

2. `test_base128_big()` uses two 256-bit boundary-style values: (2^{256}-1) and (2^{256}). The helper checks encode/decode status and asserts that the decoded `bignumber` equals the source. These cases extend coverage beyond the fixed 64-bit table, but do not establish exhaustive behavior for arbitrarily large inputs or malformed/truncated Base128 streams.

### 2.7 Huffman table learning, import and HTTP/2 streaming

1. `test_huffman()` learns a code table from a fixed English sentence using `load()`, `learn()` and `infer()`. It exports the table, asserts that 27 symbols are present, and checks the code strings for symbols `B`, `G`, `S` and `W`. It then encodes the sentence and exercises the decoder's error/manual-decode path. When the learned code is not directly decodable, the test expects ordinary decode to report an error, then calls decode with `manual_decode` and compares the resulting text with the source. If the code is unexpectedly directly decodable, the test deliberately fails through an `unexpected` assertion.

2. The test imports the learned table into a second Huffman instance, compares its encoded bytes with the first instance's output, and compares decoded text. A third instance imports the HTTP/2 Huffman table `_h2hcodes` associated with RFC 7541 Appendix B; it encodes and decodes the same sample and checks the output against the earlier decoded result. The RFC table is therefore used as a fixed table source, while the sentence's encoded bytes are generated during the test rather than compared with a separate fixed RFC string.

3. `test_huffman_stream()` uses `http_huffman_coding` to generate a reference encoded byte sequence for a fixed sentence. It then writes the input to an `encoder_stream` in chunk sizes 1 through 16 and asserts that each encoded result equals the reference. The decoder half writes the encoded bytes in chunk sizes 1 through 16 and asserts that each decoded result equals the original sentence bytes. This is a chunk-boundary consistency test for the HTTP/2 Huffman stream interfaces.

### 2.8 Fixture model and schema status

1. The encoding cases documented above construct their test inputs and expected values directly in C++ test functions or local tables; this suite does not load a YAML vector file.
2. Consequently, there is no separate YAML schema to document for `testcase/encode`. Fixed expected strings, byte arrays, integer tables and RFC examples are the fixture contracts for these cases.
3. When extending the suite, keep the oracle explicit: use a fixed expected vector for known-answer coverage, compare decoded bytes with the original for round trips, and label same-library stream/non-stream comparisons as consistency checks rather than independent interoperability evidence.

## 3. Evidence

### Source-level coverage

The suite has multiple oracles: fixed known-answer comparisons, round trips, streaming equivalence against a non-stream encoder, status checks, and selected length/field checks. The paths below keep those distinctions visible.

**1. Base16 — ordinary conversion and chunked stream**

```text
test_base16()
  -> string / binary_t / basic_stream overloads
  -> encode then decode
  -> compare decoded bytes/string == original
  -> selected status checks

test_base16_stream()
  -> input bytes 00..FF
  -> encoder_stream(encoding_base16)
  -> write random chunks of 1..16 bytes
  -> encoder.str()
  -> decoder_stream(encoding_base16)
  -> write encoded text in random chunks of 1..16 bytes
  -> decoder.data()
  -> prepend zero if decoded byte count is odd
  -> compare decoded bytes == original 256 bytes
```

The stream test checks round-trip preservation across variable chunk boundaries. Its chunk partition is random rather than a fixed vector. `test_base16_oddsize()` only asserts that one decoded vector has 66 bytes; it does not compare all bytes against a separate expected buffer.

**2. Base16 RFC-style input**

```text
RFC-style text
  -> base16_decode_rfc()
  -> valid input: compare decoded bytes with expected hex
  -> selected invalid values (out-of-range decimal / oversized hex token)
       -> assert decoded result is empty
```

Cases also cover brackets, separators, whitespace, `0x` prefixes and odd-length leading nibbles. Inputs with empty tokens are deliberately accepted after the implementation's skip/normalization behavior; they are not negative tests.

**3. Base64 and Base64URL streams**

```text
input bytes 00..FF
  -> non-stream base64_encode() -> reference encoded text
  -> encoder_stream(Base64 or Base64URL)
       -> chunk sizes 1..16
       -> compare each encoded result == reference text

reference text
  -> decoder_stream(Base64 or Base64URL)
       -> chunk sizes 1..16
       -> compare each decoded result == original 256 bytes
```

The encoder reference is produced by the same library's non-stream encoder. This establishes stream/non-stream consistency for the selected data, not independent interoperability.

**4. Base64 multiline formatting**

```text
fixed sentence
  -> base64_encode_multiline(column=80 / 0)
  -> compare exact wrapped / unwrapped text
  -> decode each form
  -> compare decoded bytes == original

same encoded content with spaces / LF / CRLF / TAB
  -> base64_decode_multiline()
  -> compare decoded bytes == original

256-byte input + selected column widths
  -> encode and split on LF
  -> compare observed line-length vector == derived expected vector
```

The boundary subtest compares line lengths, not a separately fixed complete encoded string for every width.

**5. RFC 4880 Radix-64 and armor**

```text
fixed bytes [14 FB 9C 03 D9 7E], lengths 6 / 5 / 4
  -> radix64_armor_encode()
  -> compare encoded text == RFC expected
  -> compare CRC == RFC expected
  -> radix64_armor_decode()
  -> compare decoded bytes == input prefix

ASCII-armored message
  -> scan lines / collect payload and CRC text
  -> compare extracted payload + CRC strings
  -> radix64_armor_decode()
  -> compare decoded bytes == fixed expected bytes
```

These are selected valid examples. They do not prove all malformed armor layouts or CRC failure paths are covered.

**6. Base128 integer vectors**

```text
fixed integer cases
  -> base128 encode
  -> compare encoded bytes == expected vector
  -> decode
  -> compare integer + consumed input position

selected 256-bit bignumber values
  -> encode / decode
  -> compare decoded bignumber == source
```

The large-number path checks selected values, not arbitrary widths or all malformed/truncated streams.

**7. Generic Huffman table and HTTP/2 Huffman stream**

```text
generic Huffman:
sample text -> load().learn().infer()
  -> export table
  -> compare table size + selected symbol codes
  -> encode
  -> if not decodable:
       ordinary decode -> assert error
       manual_decode -> compare decoded text == original
  -> import table into second instance
  -> compare encoded bytes / decoded text
  -> import HTTP/2 table
  -> encode/decode selected sample
  -> compare decoded text

HTTP/2 stream:
sample text -> http_huffman_coding::encode() -> reference bytes
  -> encoder_stream(encoding_h2hcodes), chunk sizes 1..16
  -> compare each encoded result == reference bytes
reference bytes -> decoder_stream(encoding_h2hcodes), chunk sizes 1..16
  -> compare each decoded result == original text bytes
```

The HTTP/2 stream reference is produced by the same implementation, so this is chunk-boundary consistency. The generic learned-table output is not compared with an independent fixed encoded vector. The selected RFC 7541 table and symbol codes do not establish exhaustive invalid-code handling.


The shared [Test Report Snapshot](../test-report-status.md) records the supplied `encode` report as **Revision 1104 · MinGW64/GCC · CTest (run context supplied by the maintainer)**: 215 pass, 0 expt, 0 fail, 0 skip and 0 triv entries.

The report summary includes Base16 conversion and stream cases, RFC-style Base16 cases, Base64 conversion and streaming cases for both alphabets, multiline formatting, RFC 4880 Radix-64/armor cases, Huffman coding, and Base128. These are recorded testcase outcomes from the supplied report; the report files do not independently identify the tested source commit, exact compiler version, build flags or full command line.

The source assertions support the specific coverage described in **How**. They do not establish exhaustive malformed-input coverage, comprehensive boundary coverage for every encoder, or interoperability against independent implementations. In particular, some tests use a library-produced encoding as the reference for a second interface, and some checks validate status or length rather than every output byte.

No tests were executed as part of this documentation update. The snapshot is retained as historical evidence and should be replaced only when a newer report with its run context is supplied.



## 4. Relationships

- [`sdk/base/encoding/`](../../../sdk/base/encoding/README.md) — implementation-side encoding module overview.
- [`test/testcase/CMakeLists.txt`](../CMakeLists.txt) and [`CMakeLists.txt`](CMakeLists.txt) — testcase target registration and source collection.
- [`sample.cpp`](sample.cpp) and [`sample.hpp`](sample.hpp) — shared entry point, command-line options and testcase declarations.
- [`testcase_base16.cpp`](testcase_base16.cpp) — Base16 and RFC-style hexadecimal cases.
- [`testcase_base64.cpp`](testcase_base64.cpp) — Base64/Base64URL, multiline formatting and Radix-64 armor cases.
- [`testcase_base128.cpp`](testcase_base128.cpp) — Base128 integer and bignumber cases.
- [`testcase_huffman.cpp`](testcase_huffman.cpp) — generic Huffman and HTTP/2 Huffman cases.
- [Test Report Snapshot](../test-report-status.md) — shared runtime evidence and provenance.

## 5. References

- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880), Sections 6.5–6.6 — Radix-64 conversions and ASCII-armored message example.
- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541), Appendix B — Huffman code table used by the HTTP/2 Huffman tests.
