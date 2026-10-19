## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                         │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Encoding testcases

## Purpose

The encoding testcase group exercises the reusable encoders and decoders in `sdk/base/encoding`: Base16, Base64/Base64URL, Base128, Radix-64 armor, generic Huffman coding, HTTP/2 Huffman coding, and incremental encoder/decoder streams. The tests are organized by behavior and protocol examples rather than one source file per public header.

## Test sources and responsibilities

| Source | Source-level checks visible in the testcase |
|---|---|
| `testcase_base16.cpp` | Base16 encode/decode across `std::string`, `binary_t`, and `basic_stream`; stream round-trip; odd-size input; RFC-style separated hexadecimal input. |
| `testcase_base64.cpp` | Base64 encode/decode, Base64URL, chunked encoder/decoder streams, multiline and no-wrap behavior, boundary columns, RFC 4880 Radix-64 vectors and CRC, and ASCII-armored message processing. |
| `testcase_base128.cpp` | Fixed vectors, two encode/decode paths, decoded input-position consumption, and `bignumber` encode/decode round-trip. |
| `testcase_huffman.cpp` | Learned/imported Huffman tables, selected code values, encode/decode, error-path behavior, RFC 7541 Appendix B, and HTTP/2 Huffman streaming with varied chunk sizes. |
| `sample.cpp`, `sample.hpp` | Shared test data/helpers used by the encoding testcase sources. |

## Coverage quality from source inspection

The suite includes meaningful equality assertions for encoded vectors and decoded values. It also checks that Base128 decoding advances the position to the end of the consumed representation, and that streaming output matches expected output or the original input when chunk boundaries vary. Protocol examples provide additional fixed-vector checks: RFC 4880 Radix-64/armor and RFC 7541 HTTP/2 Huffman.

This is stronger than a pure smoke test, but it is not exhaustive proof of malformed-input behavior, all boundary values, or interoperability with independent implementations. In `testcase_huffman.cpp`, the error-path assertions should be interpreted in context: some calls explicitly expect an error, and one assertion marked `unexpected` is a guard against reaching an invalid path rather than a normal success criterion.

## Report snapshot

The supplied `testcase-reports.zip` contains `test/testcase/encode/report`, whose summary records **215 pass, 0 expt, 0 fail, 0 skip, and 0 triv** across the listed encoding groups. The report breaks down as follows:

| Report group | Pass |
|---|---:|
| Base16 encoding | 9 |
| Base16 encoder/decoder stream | 1 |
| RFC-style Base16 (`b16 encoding`) | 1 |
| `base16_rfc` | 11 |
| Base64 encoding | 9 |
| Base64 stream | 32 |
| Base64URL stream | 32 |
| Base64 multiline | 14 |
| RFC 4880 section 6.5 Radix-64 | 15 |
| RFC 4880 section 6.6 ASCII-armored message | 4 |
| Huffman codes | 45 |
| Base128 | 42 |
| **Total** | **215** |

These counts describe the supplied report, not a fresh execution performed during documentation work. The report does not identify the operating system, compiler, build configuration, or exact source revision, so it cannot independently establish that the run was made from revision 1104.

## Documentation completeness

**Good coverage of the principal paths.** The module documents and testcase sources together explain ordinary data encoding, protocol-specific wrappers, and incremental processing. The report includes the expected groups for the four testcase source files.

## Verification completeness

**Meaningful vector and round-trip checks are present; edge-case coverage remains bounded.** Explicit assertions cover representative conversions, stream chunking, protocol examples, and Base128 position consumption. The report has no recorded failures, but that status is limited to the supplied run and its unknown environment/revision.

## Runtime execution status

- Source-level review: completed against the revision-1104 source archive.
- Supplied report: 215 pass; no failure/skip/expected-failure/trivial entries in its summary.
- Fresh runtime execution in this documentation pass: **not performed**.
- Report environment and source revision: **not identified**.

## Related source

- `sdk/base/encoding/README.md`
- `sdk/base/encoding/base16.md`
- `sdk/base/encoding/base64.md`
- `sdk/base/encoding/base128.md`
- `sdk/base/encoding/radix64.md`
- `sdk/base/encoding/huffman_coding.md`
- `sdk/base/encoding/encoder_stream.md`
- `sdk/base/encoding/decoder_stream.md`
- `test/testcase/encode/testcase_base16.cpp`
- `test/testcase/encode/testcase_base64.cpp`
- `test/testcase/encode/testcase_base128.cpp`
- `test/testcase/encode/testcase_huffman.cpp`
