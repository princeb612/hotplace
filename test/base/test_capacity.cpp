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

#define TESTVECTOR_ENTRY(e1, e2) \
    { e1, e2 }

void test_byte_capacity_unsigned() {
    _test_case.begin("byte capacity");
    struct testvector {
        uint128 x;
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
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity(entry.x);
        _logger->writeln("%032I128x -> %i", entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
    }
}

void test_byte_capacity_signed() {
    _test_case.begin("byte capacity");
    struct testvector {
        int128 x;
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
        TESTVECTOR_ENTRY(-2147483648, 4),
        TESTVECTOR_ENTRY(549755813887, 5),
        TESTVECTOR_ENTRY(-549755813888, 5),
        TESTVECTOR_ENTRY(140737488355327, 6),
        TESTVECTOR_ENTRY(-140737488355328, 6),
        TESTVECTOR_ENTRY(36028797018963967, 7),
        TESTVECTOR_ENTRY(-36028797018963968, 7),
        TESTVECTOR_ENTRY(9223372036854775807, 8),
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
    };
    for (auto entry : _table) {
        int bytesize = byte_capacity_signed<int128>(entry.x);
        _logger->writeln("%40I128i %032I128x (%i bytes)", entry.x, entry.x, bytesize);
        _test_case.assert(bytesize == entry.expect, __FUNCTION__, "(%2i) byte capacity %032I128x %I128i", bytesize, entry.x, entry.x);
    }
}
