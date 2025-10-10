/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @remarks
 *      RFC 7541 HPACK: Header Compression for HTTP/2
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void do_test_huffman_codes_routine(const char* sample, const char* expect) {
    if (sample && expect) {
        const OPTION& option = _cmdline->value();

        return_t ret = errorcode_t::success;
        binary_t bin;

        auto huffcode = http_huffman_coding::get_instance();

        // encode
        {
            basic_stream bs;
            huffcode->encode(&bs, (byte_t*)sample, strlen(sample));
            if (option.verbose) {
                test_case_notimecheck notimecheck(_test_case);
                _logger->writeln("%s", bs.c_str());
            }

            huffcode->encode(bin, (byte_t*)sample, strlen(sample));
            if (option.verbose) {
                test_case_notimecheck notimecheck(_test_case);
                _logger->dump(bin);
            }

            _test_case.assert(bin == base16_decode_rfc(expect), __FUNCTION__, "encode %s", sample);
        }

        // decode
        {
            basic_stream bs;
            ret = huffcode->decode(&bs, &bin[0], bin.size());
            if (option.verbose) {
                test_case_notimecheck notimecheck(_test_case);
                _logger->writeln("%s", bs.c_str());
            }

            _test_case.assert(((errorcode_t::success == ret) && (bs == basic_stream(sample))), __FUNCTION__, "decode %s", sample);
        }
    }
}

void test_huffman_codes() {
    _test_case.begin("RFC 7541 Appendix B. Huffman Code");

    struct huffman_coding_testvector {
        const char* sample;
        const char* expect;
    } vector[] = {
        {
            "www.example.com",
            "f1e3 c2e5 f23a 6ba0 ab90 f4ff",
        },
        {
            "no-cache",
            "a8eb 1064 9cbf",
        },
        {
            "custom-key",
            "25a8 49e9 5ba9 7d7f",
        },
        {
            "custom-value",
            "25a8 49e9 5bb8 e8b4 bf",
        },
        {
            "still a man hears what he wants to hear and disregards the rest - The boxer, Simon and Garfunkel",
            "424d450a0d4a4752939476214f138d2a4e553c0ea4a1449d49ca3b141d5229219161661d922144ce552c2a12a2ca6f9caa467f25b3e94dc6a4f5283aa45310ec96daba968f",
        },
        {
            "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw",
            "e455243d5fe92a5740fd1aa9948ca41da82a9e0aa4d61fc287a24fb53c1549ac3f850f448a46520ed4154f0551093d6a5740fd1aa99751653114f64c552e96ca87648a6e9c7e3f",
        },
    };
    for (size_t i = 0; i < RTL_NUMBER_OF(vector); i++) {
        huffman_coding_testvector* item = vector + i;
        do_test_huffman_codes_routine(item->sample, item->expect);
    }
}
