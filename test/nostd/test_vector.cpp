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

void test_vector() {
    _test_case.begin("vector");

    t_vector<int> v1;
    v1.push_back(1);
    v1.push_back(2);
    v1.push_back(3);

    _logger->writeln("case 1");
    _logger->writeln([&](basic_stream& bs) -> void { print<t_vector<int>, basic_stream>(v1, bs); });

    _test_case.assert(3 == v1.size(), __FUNCTION__, "case 1");
    _test_case.assert((1 == v1[0]) && (2 == v1[1]) && (3 == v1[2]), __FUNCTION__, "case 2");

    t_vector<int> v2(v1);
    t_vector<int> v3(std::move(v1));

    _test_case.assert(3 == v2.size(), __FUNCTION__, "case 3");
    _test_case.assert(3 == v3.size(), __FUNCTION__, "case 4");
    _test_case.assert(0 == v1.size(), __FUNCTION__, "case 5");
}
