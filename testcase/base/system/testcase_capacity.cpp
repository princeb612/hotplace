/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_capacity.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_byte_capacity_unsigned() {
    _test_case.begin("byte capacity");

    struct testvector {
        uint64 x;
        int expect;
    } _table[] = {
        {0x1, 1}, {0x8, 1}, {0x80, 1}, {0x800, 2}, {0x8000, 2}, {0x80000, 3}, {0x800000, 3}, {0x8000000, 4}, {0x80000000, 4},
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity(entry.x);
        _logger->writeln("%016I64x -> %i", entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %016I64x %I64u", bytesize, entry.x, entry.x);
    }
}

void test_byte_capacity_signed() {
    _test_case.begin("byte capacity");
    typedef int64 signed_t;
    int bits = 8;

    for (int n = 1; n <= bits; n++) {
        int64 min_val = -((int64)1 << (8 * n - 1));
        int64 max_val = ((int64)1 << (8 * n - 1)) - 1;
        _logger->writeln("byte capacity %i min %I64i ~ max %I64i", n, min_val, max_val);
    }

    struct testvector {
        int64 x;
        int expect;
    } _table[] = {
        {127, 1}, {-128, 1}, {128, 2}, {-129, 2}, {32767, 2}, {-32768, 2}, {32768, 3}, {-32769, 3}, {8388607, 3}, {-8388608, 3}, {2147483647, 4}, {-2147483648LL, 4},
    };
    for (auto entry : _table) {
        int bytesize = t_byte_capacity_signed<int64>(entry.x);
        _logger->writeln("%20I64i %016I64x (%i bytes)", entry.x, entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %016I64x %I64i", bytesize, entry.x, entry.x);
    }
}

void testcase_capacity() {
    test_byte_capacity_unsigned();
    test_byte_capacity_signed();
}
