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

void test_variant() {
    _test_case.begin("variant");

    binary_t bin;
    std::string b16stream;

    variant vt;

    vt.set_uint32(32768);
    vt.to_binary(bin, variant_convendian | variant_trunc);
    b16stream = base16_encode(bin);
    _test_case.assert(b16stream == "00008000", __FUNCTION__, "base16");

    vt.set_uint64(0x123456789LL);
    vt.to_binary(bin, variant_convendian | variant_trunc);
    b16stream = base16_encode(bin);
    _test_case.assert(b16stream == "0000000123456789", __FUNCTION__, "base16");

    bignumber bn("123456789abcdef");  // base16;
    bn.get(bin);
    _test_case.assert(base16_encode(bin) == "0123456789abcdef", __FUNCTION__, "bignumber");

    vt.set_bn(bn);
    vt.to_binary(bin, variant_convendian | variant_trunc);
    b16stream = base16_encode(bin);
    _test_case.assert(base16_encode(bin) == "0123456789abcdef", __FUNCTION__, "variant.bignumber");

    basic_stream bs;
    vtprintf(&bs, vt, vtprintf_style_debugmode);
    _logger->writeln(bs);
    _test_case.assert(bs == "0123456789abcdef (81985529216486895)", __FUNCTION__, "vtprintf variant.bignumber");
}
