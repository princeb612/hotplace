## BASE64

1. It limits the 2^8 = 256 characters that can be represented by 1 byte to 64 characters: A~Z, a~z, 0~9, +, and /.
2. It forms a basic 3-byte set and converts it into a 4-byte set.
  * 8 bits 8 bits 8 bits (24 bits) -> 6 bits 6 bits 6 bits 6 bits (24 bits)
  * If all 8 bits were used before conversion, only 6 bits are used after conversion.
  * 2^8 = 256, 2^6 = 64
  * When converting binary to ASCII, the value increases by a maximum of 4/3, and the reverse decreases by a minimum of 4/3.
3. If 4 sets are not filled after conversion, it is converted to =.

---

## BASE64URL

1. Replace + and / among the BASE64 conversion characters used in URLs with - and _.
2. Do not use =, which is used when 4 sets are not filled after conversion.

RFC 7515 JSON Web Signature (JWS) Appendix C. Notes on Implementing base64url Encoding without Padding
|Before Change|The true sign of intelligence is not knowledge but imagination.|
|:--------|:---------------------------------------------------------------------------------------|
|BASE64 |VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24uCg==|
|BASE64URL|VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24uCg |

---

## Core Mechanism

* Bit mapping: Each character represents 6 bits of data (2⁶ = 64).
* Byte grouping: Three 8-bit bytes (24 bits) convert into four 6-bit Base64 digits.
* Alphabet: Uses uppercase letters (A–Z), lowercase letters (a–z), numbers (0–9), plus + and /.
* Padding: Uses the = character at the end when input lengths are not multiples of 3 bytes.

## Radix-64 vs. Standard Base64

* ASCII Armor: Radix-64 in OpenPGP adds an optional 24-bit CRC checksum.
* Checksum format: Calculated on raw input, encoded using Base64, and appended after an extra = separator symbol.

## Key RFC Standards

* RFC 1421: Early Privacy Enhancement for Internet Electronic Mail (PEM), defining early radix-64 usage.
* RFC 2045: Defines Base64 for MIME content-transfer encoding.
* RFC 4648: The current authoritative standard for Base16, Base32, and Base64 data encodings.
* RFC 4880: OpenPGP specification that explicitly defines Radix-64 with CRC.

## study notes

* [base16](base16.md)
* [base64](base64.md)
* [huffman_coding](huffman_coding.md)
* [encoder_stream](encoder_stream.md)
* [decoder_stream](decoder_stream.md)
