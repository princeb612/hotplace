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

void test_integer_range() {
    t_integer_range<uint16> ui16;
    t_integer_range<int16> i16;
    t_integer_range<uint32> ui32;
    t_integer_range<int32> i32;
    t_integer_range<uint64> ui64;
    t_integer_range<int64> i64;
    t_integer_range<uint128> ui128;
    t_integer_range<int128> i128;

    _test_case.assert(uint16(-1) == ui16.getmax(), __FUNCTION__, "uint16 max");
    _test_case.assert(uint32(-1) == ui32.getmax(), __FUNCTION__, "uint32 max");
    _test_case.assert(uint64(-1) == ui64.getmax(), __FUNCTION__, "uint64 max");
    _test_case.assert(uint128(-1) == ui128.getmax(), __FUNCTION__, "uint128 max");

    _test_case.assert(int16(0x8000) == i16.getmin(), __FUNCTION__, "int16 min");
    _test_case.assert(int16(0x7fff) == i16.getmax(), __FUNCTION__, "int16 max");
    _test_case.assert(int32(0x80000000) == i32.getmin(), __FUNCTION__, "int32 min");
    _test_case.assert(int32(0x7fffffff) == i32.getmax(), __FUNCTION__, "int32 max");
    _test_case.assert(int64(0x8000000000000000) == i64.getmin(), __FUNCTION__, "int64 min");
    _test_case.assert(int64(0x7fffffffffffffff) == i64.getmax(), __FUNCTION__, "int64 max");
    _test_case.assert(t_atoi<int128>("-170141183460469231731687303715884105728") == i128.getmin(), __FUNCTION__, "int128 min");
    _test_case.assert(t_atoi<int128>("170141183460469231731687303715884105727") == i128.getmax(), __FUNCTION__, "int128 max");
}

void test_sampling() {
    bool test = false;
    t_sampling_range<int> sample;
    auto expect = [&](int emin, int emax) -> bool {
        int imin = sample.getmin();
        int imax = sample.getmax();
        bool cond1 = (emin == imin);
        bool cond2 = (emax == imax);
        bool ret = (cond1 && cond2);
        _test_case.assert(ret, __FUNCTION__, "sampling (%i == min) && (%i == max)", imin, imax);
        return ret;
    };

    sample.test(1);
    expect(1, 1);
    sample.test(-1);
    expect(-1, 1);
    sample.test(2);
    expect(-1, 2);
    sample.test(-2);
    expect(-2, 2);
}

void test_range() {
    _test_case.begin("range");

    test_integer_range();
    test_sampling();
}
