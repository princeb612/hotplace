/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_base16.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/encode/sample.hpp>

void test_base128() {
    _test_case.begin("base128");

    struct testvector {
        uint64 value;
        const char* expect;
    } table[] = {
        {0, "00"}, {127, "7f"}, {128, "81 00"}, {255, "81 7f"}, {16383, "ff 7f"}, {16384, "81 80 00"},
    };
    for (const auto& entry : table) {
        binary_t bin_expect = base16_decode_rfc(entry.expect);
        {
            size_t pos = 0;
            binary_t bin;

            base128_encode(entry.value, bin);
            _test_case.assert(bin == bin_expect, __FUNCTION__, "encode#1 %i", entry.value);

            uint64 value = 0;
            base128_decode(bin.data(), bin.size(), pos, value);
            _test_case.assert(value == entry.value, __FUNCTION__, "decode#1 %i", entry.value);
            _test_case.assert(pos == bin.size(), __FUNCTION__, "consume complete stream#1 %i", entry.value);
        }

        {
            binary_t bin_stream;
            binary_t bin_value;
            auto be_value = hton64(entry.value);
            base128_encode((byte_t*)&be_value, sizeof(be_value), bin_stream);
            _test_case.assert(bin_stream == bin_expect, __FUNCTION__, "encode#2 %i", entry.value);

            uint64 value = 0;
            size_t pos = 0;
            base128_decode(bin_stream.data(), bin_stream.size(), pos, bin_value);
            _test_case.assert(pos == bin_stream.size(), __FUNCTION__, "consume complete stream#2 %i", entry.value);

            bignumber bn(bin_value);
            value = bn.t_bntoi<uint64>();
            _test_case.assert(value == entry.value, __FUNCTION__, "decode#2 %i", entry.value);
        }
    }
}

void do_test_base128_big(const bignumber& bn) {
    return_t ret = errorcode_t::success;
    binary_t bin;
    ret = base128_encode(bn, bin);
    _test_case.test(ret, __FUNCTION__, "base128_encode using bignumber");

    _logger->write([&](basic_stream& dbs) -> void {
        valist va;
        va << bn.hex() << bin;
        dbs.vaprintln("source   {1}", va);
        dbs.vaprintln("encoding {2:x}", va);
    });

    bignumber bn2;
    ret = base128_decode(bin, bn2);
    _test_case.test(ret, __FUNCTION__, "base128_decode using bignumber");
    _test_case.assert(bn == bn2, __FUNCTION__, "base128_decode using bignumber");
}

void test_base128_big() {
    // worst cases
    {
        // source   ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        // encoding 8fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
        bignumber bn(1);
        bn <<= 256;
        bn -= 1;
        do_test_base128_big(bn);
    }
    {
        // source   010000000000000000000000000000000000000000000000000000000000000000
        // encoding 90808080808080808080808080808080808080808080808080808080808080808080808000
        bignumber bn(1);
        bn <<= 256;
        do_test_base128_big(bn);
    }
}

void testcase_base128() {
    test_base128();
    test_base128_big();
}
