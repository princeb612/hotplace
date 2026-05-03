/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_range.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_sampling() {
    _test_case.begin("range");
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

    sample.sampling(1);
    expect(1, 1);
    sample.sampling(-1);
    expect(-1, 1);
    sample.sampling(2);
    expect(-1, 2);
    sample.sampling(-2);
    expect(-2, 2);
}

void testcase_range() { test_sampling(); }
