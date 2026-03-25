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

#define TESTVECTOR_ENTRY(e1, e2) {e1, e2}

void test_byte_capacity_unsigned() {
    _test_case.begin("byte capacity");
    struct testvector {
#ifdef __SIZEOF_INT128__
        uint128 x;
#else
        uint64 x;
#endif
        int expect;
    } _table[] = {
        TESTVECTOR_ENTRY(0x1, 1),
        TESTVECTOR_ENTRY(0x8, 1),
        TESTVECTOR_ENTRY(0x80, 1),
        TESTVECTOR_ENTRY(0x800, 2),
        TESTVECTOR_ENTRY(0x8000, 2),
        TESTVECTOR_ENTRY(0x80000, 3),
        TESTVECTOR_ENTRY(0x800000, 3),
        TESTVECTOR_ENTRY(0x8000000, 4),
        TESTVECTOR_ENTRY(0x80000000, 4),
        TESTVECTOR_ENTRY(0x800000000, 5),
        TESTVECTOR_ENTRY(0x8000000000, 5),
        TESTVECTOR_ENTRY(0x80000000000, 6),
        TESTVECTOR_ENTRY(0x800000000000, 6),
        TESTVECTOR_ENTRY(0x8000000000000, 7),
        TESTVECTOR_ENTRY(0x80000000000000, 7),
        TESTVECTOR_ENTRY(0x800000000000000, 8),
        TESTVECTOR_ENTRY(0x8000000000000000, 8),
#ifdef __SIZEOF_INT128__
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000"), 9),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000"), 9),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000"), 10),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000"), 10),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000"), 11),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000"), 11),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000"), 12),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000"), 12),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000"), 13),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000"), 13),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000000"), 14),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000000"), 14),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000000"), 15),
        TESTVECTOR_ENTRY(t_htoi<uint128>("800000000000000000000000000000"), 15),
        TESTVECTOR_ENTRY(t_htoi<uint128>("8000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("10000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("20000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("40000000000000000000000000000000"), 16),
        TESTVECTOR_ENTRY(t_htoi<uint128>("80000000000000000000000000000000"), 16),
#endif
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity(entry.x);
#ifdef __SIZEOF_INT128__
        _logger->writeln("%032I128x -> %i", entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
#else
        _logger->writeln("%016I64x -> %i", entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %016I64x %I64i", bytesize, entry.x, entry.x);
#endif
    }
}

void test_byte_capacity_signed() {
    _test_case.begin("byte capacity");

#ifdef __SIZEOF_INT128__
    typedef int128 signed_t;
    int bits = 16;
#else
    typedef int64 signed_t;
    int bits = 8;
#endif

    for (int n = 1; n <= bits; n++) {
        signed_t min_val = -((signed_t)1 << (8 * n - 1));
        signed_t max_val = ((signed_t)1 << (8 * n - 1)) - 1;
#ifdef __SIZEOF_INT128__
        _logger->writeln("byte capacity %i min %I128i ~ max %I128i", n, min_val, max_val);
#else
        _logger->writeln("byte capacity %i min %I64i ~ max %I64i", n, min_val, max_val);
#endif
    }

    struct testvector {
        signed_t x;
        int expect;
    } _table[] = {
        TESTVECTOR_ENTRY(127, 1),
        TESTVECTOR_ENTRY(-128, 1),
        TESTVECTOR_ENTRY(128, 2),
        TESTVECTOR_ENTRY(-129, 2),
        TESTVECTOR_ENTRY(32767, 2),
        TESTVECTOR_ENTRY(-32768, 2),
        TESTVECTOR_ENTRY(32768, 3),
        TESTVECTOR_ENTRY(-32769, 3),
        TESTVECTOR_ENTRY(8388607, 3),
        TESTVECTOR_ENTRY(-8388608, 3),
        TESTVECTOR_ENTRY(2147483647, 4),
        TESTVECTOR_ENTRY(-2147483648LL, 4),  // MSVC fix
        TESTVECTOR_ENTRY(549755813887, 5),
        TESTVECTOR_ENTRY(-549755813888, 5),
        TESTVECTOR_ENTRY(140737488355327, 6),
        TESTVECTOR_ENTRY(-140737488355328, 6),
        TESTVECTOR_ENTRY(36028797018963967, 7),
        TESTVECTOR_ENTRY(-36028797018963968, 7),
        TESTVECTOR_ENTRY(9223372036854775807, 8),
#ifdef __SIZEOF_INT128__
        TESTVECTOR_ENTRY(t_atoi<int128>("-9223372036854775808"), 8),
        TESTVECTOR_ENTRY(t_atoi<int128>("2361183241434822606847"), 9),
        TESTVECTOR_ENTRY(t_atoi<int128>("-2361183241434822606848"), 9),
        TESTVECTOR_ENTRY(t_atoi<int128>("604462909807314587353087"), 10),
        TESTVECTOR_ENTRY(t_atoi<int128>("-604462909807314587353088"), 10),
        TESTVECTOR_ENTRY(t_atoi<int128>("154742504910672534362390527"), 11),
        TESTVECTOR_ENTRY(t_atoi<int128>("-154742504910672534362390528"), 11),
        TESTVECTOR_ENTRY(t_atoi<int128>("39614081257132168796771975167"), 12),
        TESTVECTOR_ENTRY(t_atoi<int128>("-39614081257132168796771975168"), 12),
        TESTVECTOR_ENTRY(t_atoi<int128>("10141204801825835211973625643007"), 13),
        TESTVECTOR_ENTRY(t_atoi<int128>("-10141204801825835211973625643008"), 13),
        TESTVECTOR_ENTRY(t_atoi<int128>("2596148429267413814265248164610047"), 14),
        TESTVECTOR_ENTRY(t_atoi<int128>("-2596148429267413814265248164610048"), 14),
        TESTVECTOR_ENTRY(t_atoi<int128>("664613997892457936451903530140172287"), 15),
        TESTVECTOR_ENTRY(t_atoi<int128>("-664613997892457936451903530140172288"), 15),
        TESTVECTOR_ENTRY(t_atoi<int128>("170141183460469231731687303715884105727"), 16),
        TESTVECTOR_ENTRY(t_atoi<int128>("-170141183460469231731687303715884105728"), 16),
#endif
    };
    for (auto entry : _table) {
#ifdef __SIZEOF_INT128__
        int bytesize = byte_capacity_signed<int128>(entry.x);
        _logger->writeln("%40I128i %032I128x (%i bytes)", entry.x, entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
#else
        int bytesize = byte_capacity_signed<int64>(entry.x);
        _logger->writeln("%20I64i %016I64x (%i bytes)", entry.x, entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %016I64x %I64i", bytesize, entry.x, entry.x);
#endif
    }
}
