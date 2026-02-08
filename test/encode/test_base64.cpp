/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void do_test_base64_routine(const char* source, size_t source_size, int encoding) {
    return_t ret = errorcode_t::success;
    basic_stream bs;
    std::string encoded_b64;
    binary_t decoded_b64;

    _test_case.reset_time();
    base64_encode((byte_t*)source, source_size, encoded_b64, encoding);
    base64_decode(encoded_b64, decoded_b64, encoding);
    _test_case.assert(0 == memcmp(source, &decoded_b64[0], source_size), __FUNCTION__, "base64_decode");

    {
        test_case_notimecheck notimecheck(_test_case);

        _logger->hdump("input", source, source_size, 16, 3);
        _logger->hdump("encoded", encoded_b64, 16, 3);
        _logger->hdump("decoded", decoded_b64, 16, 3);
    }
}

void test_base64() {
    constexpr char lyrics[] = "still a man hears what he wants to hear and disregards the rest";
    size_t len = strlen(lyrics);

    do_test_base64_routine(lyrics, len, encoding_t::encoding_base64);
    do_test_base64_routine(lyrics, len, encoding_t::encoding_base64url);
}
