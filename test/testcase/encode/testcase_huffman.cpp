/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_huffman.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/encode/sample.hpp>

void test_huffman() {
    _test_case.begin("huffman codes");
    return_t ret = errorcode_t::success;

    const char* sample = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";
    size_t samplesize = strlen(sample);
    std::map<uint8, std::string> table;

    huffman_coding huff;

    // generate the huffman table from sample
    // https://asecuritysite.com/calculators/huff
    huff.load(sample).learn().infer();

    // export table
    auto lambda_exports = [&](uint8 sym, const char* code) -> void {
        _logger->writeln("sym %c (0x%02x) code : %s (len %zi)", isprint(sym) ? sym : '?', sym, code, strlen(code));
        table.emplace(sym, code);
    };
    huff.exports(lambda_exports);
    // test table
    {
        _test_case.assert(27 == table.size(), __FUNCTION__, "exports");

        // sym B (0x42) code : 1100010 (len 7)
        // sym G (0x47) code : 1100011 (len 7)
        // sym S (0x53) code : 1100100 (len 7)
        // sym W (0x57) code : 1100101 (len 7)
        // ...

        _test_case.assert("1100010" == table['B'], __FUNCTION__, "check the code for the symbol B");
        _test_case.assert("1100011" == table['G'], __FUNCTION__, "check the code for the symbol G");
        _test_case.assert("1100100" == table['S'], __FUNCTION__, "check the code for the symbol S");
        _test_case.assert("1100101" == table['W'], __FUNCTION__, "check the code for the symbol W");
    }

    // encode
    basic_stream ebs;
    binary_t enc;
    {
        // 00000000 : CA FE EC 57 13 C8 21 5A 89 FC DE 90 59 BF 4F 9A | ...W..!Z....Y.O.
        // 00000010 : 5D 7B 0D E1 F4 F9 A5 D7 B0 DF CD E9 05 9B F4 FC | ]{..............
        // 00000020 : C9 72 F2 08 56 A2 78 3A FF 8D DA 1B F8 9A 0C 26 | .r..V.x:.......&
        // 00000030 : FE 45 A2 80 -- -- -- -- -- -- -- -- -- -- -- -- | .E..

        ret = huff.encode(enc, sample, samplesize);
        _logger->dump(enc);
        ret = huff.diag(ebs, sample, samplesize);
        _logger->writeln(ebs);
        _test_case.test(ret, __FUNCTION__, "encode");

        _logger->writeln("before %zi -> after %zi (efficiency %.2f%%)", samplesize, enc.size(), enc.size() / (float)samplesize * 100);
    }

    // manual decode (code len in bits < 5)
    // original 010110 1000 1010
    // storage  010110 1000 10100000

    basic_stream dbs;
    if (false == huff.decodable()) {
        ret = huff.decode(dbs, enc.data(), enc.size());
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "error detected");

        ret = huff.decode(dbs, enc.data(), enc.size(), manual_decode);
        _test_case.test(ret, __FUNCTION__, "error ignored");

        dbs.resize(samplesize);
        _logger->writeln(dbs);
        _test_case.assert(dbs == sample, __FUNCTION__, "decode");
    } else {
        _test_case.assert(false, __FUNCTION__, "unexpected");
    }

    // import table and test

    huffman_coding huff2;
    binary_t enc2;
    basic_stream ebs2;
    basic_stream dbs2;

    {
        huff2.imports(table);

        // encode
        ret = huff2.encode(enc2, sample, samplesize);
        _logger->dump(enc2);
        ret = huff2.diag(ebs2, sample, samplesize);
        _logger->writeln(ebs2);
        _test_case.assert(enc == enc2, __FUNCTION__, "imports+encode");
        // decode
        uint32 flags = huff2.decodable() ? 0 : manual_decode;
        ret = huff2.decode(dbs2, enc2.data(), enc2.size(), flags);
        if (flags & manual_decode) {
            dbs2.resize(samplesize);
        }
        _logger->writeln(dbs2);
        _test_case.assert(dbs == dbs2, __FUNCTION__, "imports+decode");
    }

    // RFC 7541 Appendix B. Huffman Code
    huffman_coding huff3;
    binary_t enc3;
    basic_stream ebs3;
    basic_stream dbs3;

    {
        huff3.imports(_h2hcodes);

        // encode
        ret = huff3.encode(enc3, sample, samplesize);
        _logger->dump(enc3);
        ret = huff3.diag(ebs3, sample, samplesize);
        _logger->writeln(ebs3);
        _test_case.test(ret, __FUNCTION__, "RFC 7541 Appendix B. Huffman Code");
        // decode
        uint32 flags = huff3.decodable() ? 0 : manual_decode;
        ret = huff3.decode(dbs3, enc3.data(), enc3.size(), flags);
        if (flags & manual_decode) {
            dbs3.resize(samplesize);
        }
        _logger->writeln(dbs3);
        _test_case.assert(dbs == dbs3, __FUNCTION__, "RFC 7541 Appendix B. Huffman Code");
    }
}

void test_huffman_stream() {
    _test_case.begin("huffman codes");

    const char* sample1 = "We don't playing because we grow old; we grow old because we stop playing.";
    binary_t sample = to_binary(sample1);

    binary_t encoded;
    http_huffman_coding::get_instance()->encode(encoded, sample.data(), sample.size());
    binary_t expect_encoded = encoded;

    auto write_encoder_chunks = [&](encoder_stream& encoder, const byte_t* stream, size_t stream_size, size_t chunk_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = std::min(chunk_size, stream_size - pos);
            encoder.write(stream + pos, len);
            pos += len;
        }
    };
    auto write_decoder_chunks = [&](decoder_stream& decoder, const byte_t* stream, size_t stream_size, size_t chunk_size) -> void {
        size_t pos = 0;
        while (pos < stream_size) {
            size_t len = std::min(chunk_size, stream_size - pos);
            decoder.write(stream + pos, len);
            pos += len;
        }
    };

    for (size_t chunk = 1; chunk <= 16; ++chunk) {
        encoder_stream encoder(encoding_t::encoding_h2hcodes);
        _logger->writeln("start encoding");
        write_encoder_chunks(encoder, sample.data(), sample.size(), chunk);
        _logger->writeln("stop encoding");
        auto encoded = encoder.bin();  // always even size

        valist va;
        va << chunk << sample << encoded;
        _logger->write([&](basic_stream& bs) -> void {
            bs.vaprintln("chunk   {1}", va);
            bs.vaprintln("source  {2:s}", va);
            bs.vaprintln("encoded {3:s}", va);  // printable data
        });

        _test_case.assert(encoded == expect_encoded, __FUNCTION__, "http_huffman_coding encoder stream chunk %zi", chunk);
    }

    for (size_t chunk = 1; chunk <= 16; ++chunk) {
        decoder_stream decoder(encoding_t::encoding_h2hcodes);
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
        _test_case.assert(decoded == sample, __FUNCTION__, "http_huffman_coding decoder stream chunk %zi", chunk);
    }
}

void testcase_huffman() {
    test_huffman();
    test_huffman_stream();
}
