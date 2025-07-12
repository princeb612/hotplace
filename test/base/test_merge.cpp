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

void test_merge() {
    _test_case.begin("merge");

    {
        t_merge_ovl_intervals<size_t> moi;
        moi.add(0, 1).add(1, 31);
        auto res = moi.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.s, item.e);
        }
        _test_case.assert(1 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == t_merge_ovl_intervals<size_t>::interval(0, 31), __FUNCTION__, "res[0]");
    }

    _test_case.begin("merge (subtract)");

    {
        t_merge_ovl_intervals<uint8> moi;
        moi.add(1, 4).add(6, 10).subtract(3, 7);
        auto res = moi.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.s, item.e);
        }
        _test_case.assert(2 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == t_merge_ovl_intervals<uint8>::interval(1, 2), __FUNCTION__, "res[0]");
        _test_case.assert(res[1] == t_merge_ovl_intervals<uint8>::interval(8, 10), __FUNCTION__, "res[1]");
    }

    {
        t_merge_ovl_intervals<int> moi;
        moi.add(1, 4).add(6, 10).subtract(1, 7);
        auto res = moi.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.s, item.e);
        }
        _test_case.assert(1 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == t_merge_ovl_intervals<int>::interval(8, 10), __FUNCTION__, "res[0]");
    }

    {
        t_merge_ovl_intervals<int> moi;
        moi.add(-10, 4).add(6, 10).subtract(-3, 8);
        auto res = moi.merge();
        for (auto item : res) {
            _logger->writeln("%i %i", item.s, item.e);
        }
        _test_case.assert(2 == res.size(), __FUNCTION__, "res");
        _test_case.assert(res[0] == t_merge_ovl_intervals<int>::interval(-10, -4), __FUNCTION__, "res[0]");
        _test_case.assert(res[1] == t_merge_ovl_intervals<int>::interval(9, 10), __FUNCTION__, "res[1]");
    }
}
