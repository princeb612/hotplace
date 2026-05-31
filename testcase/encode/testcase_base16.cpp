/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_base16.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/encode/sample.hpp>

void test_base16() {
    _test_case.begin("base16 encoding");

    return_t ret = errorcode_t::success;

    const char* sample1 = "We don't playing because we grow old; we grow old because we stop playing.";
    const char* sample2 = R"(0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_=+[{]}\\|;:'",<.>/\?)";
    /* comparison */
    binary_t bin_sample1(sample1, sample1 + strlen(sample1));
    binary_t bin_sample2(sample2, sample2 + strlen(sample2));
    basic_stream bs_sample1(sample1);
    basic_stream bs_sample2(sample2);

    {
        auto encoded = base16_encode(sample1);
        auto decoded = base16_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == bin_sample1, __FUNCTION__, "base16 encoding #1");
    }

    {
        auto encoded = base16_encode(sample2);
        auto decoded = base16_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == bin_sample2, __FUNCTION__, "base16 encoding #2");
    }

    {
        std::string encoded;
        std::string decoded;
        ret = base16_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        ret = base16_decode(encoded, decoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1}", va);
            bs.vaprintln("decoded {2}", va);
        });
        _test_case.test(ret, __FUNCTION__, "decode");
        _test_case.assert(bs_sample1 == decoded, __FUNCTION__, "base16 encoding #3 std::string");
    }

    {
        binary_t encoded;
        binary_t decoded;
        ret = base16_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        decoded = base16_decode(encoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1:s}", va);  // printable binary data
            bs.vaprintln("decoded {2:s}", va);  // printable binary data
        });
        _test_case.assert(decoded == bin_sample1, __FUNCTION__, "base16 encoding #4 binary_t");
    }

    {
        basic_stream encoded;
        basic_stream decoded;
        ret = base16_encode((const byte_t*)sample1, strlen(sample1), encoded);
        _test_case.test(ret, __FUNCTION__, "encode");
        base16_decode(encoded.c_str(), encoded.size(), decoded);
        _logger->write([&](basic_stream& bs) -> void {
            valist va;
            va << encoded << decoded;
            bs.vaprintln("encoded {1:s}", va);
            bs.vaprintln("decoded {2:s}", va);
        });
        _test_case.assert(decoded == bs_sample1, __FUNCTION__, "base16 encoding #5 basic_stream");
    }
}

void test_base16_stream() {
    _test_case.begin("base16 encoder/decoder stream");

    const size_t bufsize_test = 256;
    binary_t sample;
    sample.reserve(bufsize_test);
    for (size_t i = 0; i < bufsize_test; ++i) {
        sample.push_back((uint8)i);
    }

    auto write_encoder_chunks = [&](encoder_stream& encoder, const byte_t* stream, size_t stream_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = (std::rand() % 16) + 1;
            len = std::min(len, stream_size - pos);
            encoder.write(stream + pos, len);
            // _logger->writeln("write into encoder stream %zi bytes", len);
            pos += len;
        }
    };
    auto write_decoder_chunks = [&](decoder_stream& decoder, const char* stream, size_t stream_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = (std::rand() % 16) + 1;
            len = std::min(len, stream_size - pos);
            decoder.write(stream + pos, len);
            // _logger->writeln("write into decoder stream %zi bytes", len);
            pos += len;
        }
    };

    encoder_stream encoder(encoding_t::encoding_base16);
    _logger->writeln("start encoding");
    write_encoder_chunks(encoder, sample.data(), sample.size());
    _logger->writeln("stop encoding");
    auto encoded = encoder.str();

    valist va;
    va << sample << encoded;
    _logger->writeln([&](basic_stream& bs) -> void {
        bs.vaprintln("{1:s}", va);
        bs.vaprintln("{2}", va);
    });

    decoder_stream decoder(encoding_t::encoding_base16);
    _logger->writeln("start decoding");
    write_decoder_chunks(decoder, encoded.data(), encoded.size());
    _logger->writeln("stop decoding");
    auto decoded = decoder.data();
    if (decoded.size() % 2) {
        decoded.insert(decoded.begin(), 0);  // if odd size, preserve leading zero
    }

    va << decoded;
    _logger->writeln([&](basic_stream& bs) -> void {
        bs.vaprintln("{2}", va);
        bs.vaprintln("{3:s}", va);
    });
    _test_case.assert(decoded == sample, __FUNCTION__, "base16 encoder/decoder stream");
}

void test_base16_oddsize() {
    _test_case.begin("b16 encoding");
    const char* test = "0cef3f4babe6f9875e5db28c27d6a197d607c3641a90f10c2cc2cb302ba658aa151dc76c507488b99f4b3c8bb404fb5c852f959273f412cbdd5e713c5e3f0e67f94";
    binary_t bin_test = base16_decode(test);

    {
        test_case_notimecheck notimecheck(_test_case);

        basic_stream bs;
        dump_memory(bin_test, &bs);
        _logger->writeln("%s", bs.c_str());
    }

    _test_case.assert(66 == bin_test.size(), __FUNCTION__, "odd size");
}

void do_dump_base16_rfc(const char* text, const char* input) {
    basic_stream bs;

    std::string encoded = base16_encode_rfc(input);
    binary_t decoded = base16_decode(encoded);
    dump_memory(decoded, &bs, 16, 4);
    _logger->writeln("%s\n  input   %s\n  encoded %s\n  decoded\n%s", text, input, encoded.c_str(), bs.c_str());
}

void test_base16_rfc() {
    _test_case.begin("base16_rfc");

    constexpr char expr1[] = "[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]";  // e3 c5 75 fc 2 db e9 44 b4 e1 4d db
    constexpr char expr2[] = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
    constexpr char expr3[] =
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f";

    do_dump_base16_rfc("case1", expr1);
    do_dump_base16_rfc("case2", expr2);
    do_dump_base16_rfc("case3", expr3);
}

void testcase_base16() {
    test_base16();
    test_base16_stream();
    test_base16_oddsize();
    test_base16_rfc();
}
