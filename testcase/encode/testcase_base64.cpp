/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_base64.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/encode/sample.hpp>

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
            bs.vaprintln("chunk   {1:s}", va);
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
            bs.vaprintln("chunk   {1:s}", va);
            bs.vaprintln("decoded {2:s}", va);  // printable data
        });
        _test_case.assert(decoded == sample, __FUNCTION__, "base64 decoder stream chunk %zi", chunk);
    }
}

void test_base64_stream() {
    test_base64_stream_by_encoding("base64", encoding_t::encoding_base64);
    test_base64_stream_by_encoding("base64url", encoding_t::encoding_base64url);
}

void testcase_base64() {
    test_base64();
    test_base64_stream();
}
