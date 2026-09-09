/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_bitset.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/base/sample.hpp>

void test_bitset() {
    _test_case.begin("bitset");

    t_bit_set<int> bs(0, 255);
    binary_t bin;

    const int values[] = {-5, -3, -1, 1, 3, 5, 7, 9, 11, 13, 15};  // -5, -3, -1 is not valid
    for (const auto& item : values) {
        bs.add(item);
    }
    const int values2[] = {1, 3, 5, 7, 9, 11, 13, 15};
    for (const auto& item : values2) {
        auto test = bs.has(item);
        _test_case.assert(test, __FUNCTION__, "has %i", item);
    }

    const int values3[] = {1, 5, 9, 13};
    for (const auto& item : values3) {
        bs.subtract(item);
    }
    bin = std::move(bs.get());
    auto encoded = base16_encode(bin);
    _logger->writeln("encoded %s", encoded.c_str());

    bs.clear();

    for (const auto& item : values) {
        auto test = bs.has(item);
        _test_case.nassert(test, __FUNCTION__, "has not %i", item);
    }
}

void testcase_bitset() { test_bitset(); }
