/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_endian.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_convert_endian() {
    _test_case.begin("endian");
    {
        int16 i = 0x1234;
        int16 a = htons(i);
        int16 b = convert_endian(i);
        _test_case.assert(a == b, __FUNCTION__, "hton16 %x %x", a, b);
    }

    {
        int32 i = 0x12345678;
        int32 a = htonl(i);
        int32 b = convert_endian(i);
        _test_case.assert(a == b, __FUNCTION__, "hton32 %x %x", a, b);
    }

    struct testvector_64 {
        uint64 h;
        uint64 n;
    } _table_64[] = {
        {
            t_htoi<uint64>("0123456789ABCDEF"),
            t_htoi<uint64>("EFCDAB8967452301"),
        },
        {
            t_htoi<uint64>("1122334455667788"),
            t_htoi<uint64>("8877665544332211"),
        },
    };

    for (auto item : _table_64) {
        _logger->dump((byte_t *)&item.h, sizeof(uint64));
        _logger->dump((byte_t *)&item.n, sizeof(uint64));
        _test_case.assert(hton64(item.h) == item.n, __FUNCTION__, "hton64 %x %x", item.h, item.n);
    }

#ifdef __SIZEOF_INT128__
    struct testvector_128 {
        uint128 h;
        uint128 n;
    } _table_128[] = {
        {
            t_htoi<uint128>("0123456789ABCDEFFEDCBA9876543210"),
            t_htoi<uint128>("1032547698BADCFEEFCDAB8967452301"),
        },
        {
            t_htoi<uint128>("00112233445566778899AABBCCDDEEFF"),
            t_htoi<uint128>("FFEEDDCCBBAA99887766554433221100"),
        },
    };

    for (auto item : _table_128) {
        _logger->dump((byte_t *)&item.h, sizeof(uint128));
        _logger->dump((byte_t *)&item.n, sizeof(uint128));
        _test_case.assert(hton128(item.h) == item.n, __FUNCTION__, "hton128 %x %x", item.h, item.n);
    }
#endif
}

void test_is_endian() {
    _test_case.begin("endian");
    bool ret = false;
    std::string text;

#if defined __LITTLE_ENDIAN
    text = "__LITTLE_ENDIAN__";
    bool is_le = is_little_endian();
    ret = (true == is_le);
#elif defined __BIG_ENDIAN
    text = "__BIG_ENDIAN__";
    bool is_be = is_big_endian();
    ret = (true == is_be);
#endif
    _test_case.assert((true == ret), __FUNCTION__, text.c_str());
}

void testcase_endian() {
    test_is_endian();
    test_convert_endian();
}
