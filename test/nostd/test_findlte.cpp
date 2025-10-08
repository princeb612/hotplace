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

void test_find_lessthan_or_equal() {
    _test_case.begin("find_lessthan_or_equal");

    std::set<int> container = {1, 2, 4, 7, 11, 16, 22, 29};
    std::vector<int> input = {1, 2, 3, 5, 8, 10, 12, 17, 20, 23, 30};
    std::vector<int> expect = {1, 2, 2, 4, 7, 7, 11, 16, 16, 22, 29};

    _logger->writeln([&](basic_stream& bs) -> void { print<std::set<int>, basic_stream>(container, bs); });

    for (size_t i = 0; i < input.size(); i++) {
        int value = 0;
        int point = input[i];
        find_lessthan_or_equal<int>(container, point, value);
        _test_case.assert(value == expect[i], __FUNCTION__, "%i -> %i", point, value);
    }
}
