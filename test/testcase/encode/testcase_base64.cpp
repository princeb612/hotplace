/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_base64.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/encode/sample.hpp>

void test_base64() {
    _test_case.begin("base64 encoding");

    return_t ret = errorcode_t::success;

    const char* sample1 = "We don't playing because we grow old; we grow old because we stop playing.";
    const char* sample2 = R"(0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'",<.>/\?)";
    /* comparison */
    binary_t bin_sample1(sample1, sample1 + strlen(sample1));
    binary_t bin_sample2(sample2, sample2 + strlen(sample2));
    basic_stream bs_sample1(sample1);
    basic_stream bs_sample2(sample2);

    {
        auto encoded = base64_encode(sample1);
        auto decoded = base64_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == bin_sample1, __FUNCTION__, "base64 encoding #1");
    }

    {
        auto encoded = base64_encode(sample2);
        auto decoded = base64_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == bin_sample2, __FUNCTION__, "base64 encoding #2");
    }

    {
        std::string encoded;
        std::string decoded;
        ret = base64_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        ret = base64_decode(encoded, decoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2}", va);
        });
        _test_case.test(ret, __FUNCTION__, "decode");
        _test_case.assert(bs_sample1 == decoded, __FUNCTION__, "base64 encoding #3 std::string");
    }

    {
        binary_t encoded;
        binary_t decoded;
        ret = base64_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        decoded = base64_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1:s}", va);  // printable binary data
            bs.vaprintln("decoded {2:s}", va);  // printable binary data
        });
        _test_case.assert(decoded == bin_sample1, __FUNCTION__, "base64 encoding #4 binary_t");
    }

    {
        basic_stream encoded;
        basic_stream decoded;
        ret = base64_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        base64_decode(encoded.c_str(), encoded.size(), decoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1:s}", va);
            bs.vaprintln("decoded {2:s}", va);
        });
        _test_case.assert(decoded == bs_sample1, __FUNCTION__, "base64 encoding #5 basic_stream");
    }
}

void test_base64_stream_by_encoding(std::string text, encoding_t encoding) {
    _test_case.begin("base64 encoder/decoder stream %s", text.c_str());

    const size_t bufsize_test = 256;
    binary_t sample;
    sample.reserve(bufsize_test);
    for (size_t i = 0; i < bufsize_test; ++i) {
        sample.push_back(t_narrow_cast(i));
    }

    auto write_encoder_chunks = [&](encoder_stream& encoder, const byte_t* stream, size_t stream_size, size_t chunk_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = std::min(chunk_size, stream_size - pos);
            encoder.write(stream + pos, len);
            pos += len;
        }
    };
    // important testcase
    auto write_decoder_chunks = [&](decoder_stream& decoder, const char* stream, size_t stream_size, size_t chunk_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = std::min(chunk_size, stream_size - pos);
            decoder.write(stream + pos, len);
            pos += len;
        }
    };

    std::string expect_encoded;
    base64_encode(sample, expect_encoded, encoding);

    for (size_t chunk = 1; chunk <= 16; ++chunk) {
        encoder_stream encoder(encoding);
        _logger->writeln("start encoding");
        write_encoder_chunks(encoder, sample.data(), sample.size(), chunk);
        _logger->writeln("stop encoding");
        auto encoded = encoder.str();  // always even size

        valist va;
        va << chunk << sample << encoded;
        _logger->write([&](basic_stream& bs) -> void {
            bs.vaprintln("chunk   {1}", va);
            bs.vaprintln("source  {2:s}", va);  // printable data
            bs.vaprintln("encoded {3:s}", va);
        });

        _test_case.assert(encoded == expect_encoded, __FUNCTION__, "base64 encoder stream chunk %zi", chunk);
    }

    std::string encoded;
    base64_encode(sample, encoded, encoding);

    for (size_t chunk = 1; chunk <= 16; ++chunk) {
        decoder_stream decoder(encoding);
        _logger->writeln("start decoding");
        write_decoder_chunks(decoder, encoded.data(), encoded.size(), chunk);
        _logger->writeln("stop decoding");
        auto decoded = decoder.data();

        valist va;
        va << chunk << decoded;
        _logger->write([&](basic_stream& bs) -> void {
            bs.vaprintln("chunk   {1}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == sample, __FUNCTION__, "base64 decoder stream chunk %zi", chunk);
    }
}

void test_base64_stream() {
    test_base64_stream_by_encoding("base64", encoding_t::encoding_base64);
    test_base64_stream_by_encoding("base64url", encoding_t::encoding_base64url);
}

void test_base64_multiline() {
    _test_case.begin("base64 multiline");
    const char* sample = "We don't playing because we grow old; we grow old because we stop playing.";
    const char* expect_nowrap = "V2UgZG9uJ3QgcGxheWluZyBiZWNhdXNlIHdlIGdyb3cgb2xkOyB3ZSBncm93IG9sZCBiZWNhdXNlIHdlIHN0b3AgcGxheWluZy4=";
    const char* expect_multiline = "V2UgZG9uJ3QgcGxheWluZyBiZWNhdXNlIHdlIGdyb3cgb2xkOyB3ZSBncm93IG9sZCBiZWNhdXNlIHdl\nIHN0b3AgcGxheWluZy4=";
    auto bin_sample = to_binary(sample);
    std::string encoded;

    // encode
    base64_encode_multiline((byte_t*)sample, strlen(sample), 80, encoded);
    _logger->writeln(encoded);
    _test_case.assert(encoded == expect_multiline, __FUNCTION__, "encode");

    // decode
    binary_t decoded;
    base64_decode_multiline(encoded.c_str(), encoded.size(), decoded);
    _logger->dump(decoded);
    _test_case.assert(decoded == bin_sample, __FUNCTION__, "decode");

    // \n
    const char* sample2 = "  V2UgZG9uJ3QgcGxheWluZyBiZWNhdXNlIHdlIGdyb3cgb2xkOyB3ZSBncm93IG9sZCBiZWNhdXNlIHdl  \n  IHN0b3AgcGxheWluZy4=  ";
    base64_decode_multiline(sample2, strlen(sample2), decoded);
    _logger->dump(decoded);
    _test_case.assert(decoded == bin_sample, __FUNCTION__, "decode LF");

    // \r\n
    const char* sample3 = "  V2UgZG9uJ3QgcGxheWluZyBiZWNhdXNlIHdlIGdyb3cgb2xkOyB3ZSBncm93IG9sZCBiZWNhdXNlIHdl  \r\n  IHN0b3AgcGxheWluZy4=  \r\n  ";
    base64_decode_multiline(sample3, strlen(sample3), decoded);
    _logger->dump(decoded);
    _test_case.assert(decoded == bin_sample, __FUNCTION__, "decode CR+LF");

    // \t and \r\n
    const char* sample4 = "  \tV2UgZG9uJ3QgcGxheWluZyBiZWNhdXNlIHdlIGdyb3cgb2xkOyB3ZSBncm93IG9sZCBiZWNhdXNlIHdl  \r\n\t  IHN0b3AgcGxheWluZy4=  \r\n  \t";
    base64_decode_multiline(sample4, strlen(sample4), decoded);
    _logger->dump(decoded);
    _test_case.assert(decoded == bin_sample, __FUNCTION__, "decode TAB and CR+LF");

    // if 0 == column, no line wrapping
    base64_encode_multiline((byte_t*)sample, strlen(sample), 0, encoded);
    _logger->writeln(encoded);
    _test_case.assert(encoded == expect_nowrap, __FUNCTION__, "encode no line wrapping");

    // multiline_decode nowrapped encoded string
    base64_decode_multiline(expect_nowrap, strlen(expect_nowrap), decoded);
    _test_case.assert(decoded == bin_sample, __FUNCTION__, "decode nowrap");

    // boundary test
    {
        binary_t buf;
        buf.resize(256);
        for (size_t i = 0; i < 256; ++i) buf[i] = i;

        auto lambda_boundary = [&](size_t column) -> void {
            // skip GDB step into
            auto stream = buf.data();
            auto size = buf.size();

            base64_encode_multiline(stream, size, column, encoded);
            _logger->writeln(encoded);

            std::vector<size_t> result;
            size_t pos = 0;
            size_t brk = 0;
            while (errorcode_t::success == scan(encoded.c_str(), encoded.size(), pos, &brk, "\n")) {
                result.push_back(brk - pos);
                pos = brk + 1;
            }

            std::vector<size_t> expect;
            size_t formatted_size = encoded.size();
            if (column) {
                while (true) {
                    if (formatted_size >= column) {
                        expect.push_back(column);
                        formatted_size -= column;
                        if (0 == formatted_size) break;
                        --formatted_size;  // \n
                    } else if (formatted_size < column) {
                        if (0 == formatted_size) break;
                        expect.push_back(formatted_size);
                        break;
                    }
                }
            } else {
                expect.push_back(formatted_size);  // no wrap
            }

            basic_stream bs;
            print<std::vector<size_t>, basic_stream>(result, bs);
            _logger->writeln("result : %s", bs.c_str());
            _test_case.assert(result == expect, __FUNCTION__, "boundary test %zi", column);
        };

        lambda_boundary(3);
        lambda_boundary(4);
        lambda_boundary(30);
        lambda_boundary(60);
        lambda_boundary(100);
        lambda_boundary(150);
        lambda_boundary(344);
    }
}

void test_rfc4880_6_5() {
    _test_case.begin("RFC4880 6.5.  Examples of Radix-64");

    /**
     * INPUT    testvector_rfc4880_6_5
     * OUTPUT   base64_encode
     *
     * ChatGPT review
     *
     *                 input
     *                   │
     *                   ▼
     *        radix64_armor_encode()
     *              │          │
     *              ▼          ▼
     *          radix64       CRC-24
     *              │          │
     *              └────┬─────┘
     *                   ▼
     *        radix64_armor_decode()
     *                   │
     *                   ▼
     *              decoded
     *                   │
     *                   ▼
     *            decoded == input
     */
    const byte_t testvector_rfc4880_6_5[] = {0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E};
    struct testvector {
        const byte_t* input;
        size_t size;
        const char* encoded;
        const char* crc;
    } table[] = {
        {testvector_rfc4880_6_5, 6, "FPucA9l+", "abPZ"},
        {testvector_rfc4880_6_5, 5, "FPucA9k=", "hSfQ"},
        {testvector_rfc4880_6_5, 4, "FPucAw==", "8Sh3"},
    };
    auto lambda_rfc4880_6_5 = [&](const testvector& entry) -> void {
        const byte_t* input = entry.input;
        size_t size = entry.size;
        _logger->hdump("input", input, size, 16, 3);

        std::string encoded;
        std::string crc;

        auto test = radix64_armor_encode(input, size, encoded, crc);
        _logger->write([&](basic_stream& dbs) -> void {
            valist va;
            va << encoded << crc;
            dbs.vaprintln("{1}", va);
            dbs.vaprintln("{2}", va);
        });
        _test_case.test(test, __FUNCTION__, "radix64 encode : size %zi", entry.size);
        _test_case.assert(encoded == entry.encoded, __FUNCTION__, "radix64 encode : encoded %s", entry.encoded);
        _test_case.assert(crc == entry.crc, __FUNCTION__, "radix64 encode : crc %s", entry.crc);

        binary_t decoded;
        test = radix64_armor_decode(encoded.data(), encoded.size(), crc.c_str(), crc.size(), decoded);
        _test_case.test(test, __FUNCTION__, "radix64 decode");
        _test_case.assert(decoded == binary_t(input, input + size), __FUNCTION__, "decoded == input");
    };

    for (const auto& entry : table) {
        lambda_rfc4880_6_5(entry);
    }
}

void test_rfc4880_6_6() {
    _test_case.begin("RFC4880 6.6.  Example of an ASCII Armored Message");

    // RFC 4880 Radix-64 Conversions
    // The cleartext header '-----BEGIN PGP SIGNED MESSAGE-----' on a single line
    // One or more "Hash" Armor Headers
    // Exactly one empty line not included into the message digest
    // The dash-escaped cleartext that is included into the message digest
    // The ASCII armored signature(s) including the '-----BEGIN PGP SIGNATURE-----' Armor Header and Armor Tail Lines.

    const char* message =
        "-----BEGIN PGP MESSAGE-----\n"
        "Version: OpenPrivacy 0.99\n"
        "\n"
        "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS\n"
        "vBSFjNSiVHsuAA==\n"
        "=njUN\n"
        "-----END PGP MESSAGE-----\n";

    size_t pos = 0;
    size_t brk = 0;
    size_t size = strlen(message);

    bool handle_message = false;
    std::string cleartext;
    std::string signature;

    while (errorcode_t::success == getline(message, size, pos, &brk)) {
        std::string line(message + pos, brk - pos);
        _logger->writeln(line);
        if (handle_message && false == line.empty()) {
            if (line[0] == '=') {
                handle_message = false;
                line.erase(line.begin());
                signature = std::move(line);
            } else {
                cleartext += line;
            }
        }
        if (0 == brk - pos) handle_message = true;
        pos = brk + 1;
    }

    const char* expect_cleartext = "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzSvBSFjNSiVHsuAA==";
    const char* expect_signature = "njUN";
    _test_case.assert(cleartext == expect_cleartext, __FUNCTION__, "extract cleartext");
    _test_case.assert(signature == expect_signature, __FUNCTION__, "extract signature");

    binary_t decoded;
    auto test = radix64_armor_decode(cleartext.c_str(), cleartext.size(), signature.c_str(), signature.size(), decoded);

    const char* expect_decode =
        "C8 38 01 3B 6D 96 C4 11 EF EC EF 17 EC EF E3 CA"
        "00 04 CE 89 79 EA 25 0A 89 79 95 F9 79 A9 0A D9"
        "A9 A9 05 0A 89 0A C5 A9 C9 45 A9 40 C1 A2 FC D2"
        "BC 14 85 8C D4 A2 54 7B 2E 00";

    _logger->hdump("decode", decoded, 16, 3);
    _test_case.test(test, __FUNCTION__, "decode");
    _test_case.assert(decoded == base16_decode_rfc(expect_decode), __FUNCTION__, "decode : test expectation");
}

void testcase_base64() {
    test_base64();
    test_base64_stream();
    test_base64_multiline();
    test_rfc4880_6_5();
    test_rfc4880_6_6();
}
