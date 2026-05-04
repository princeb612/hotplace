/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_int.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_atoi() {
    _test_case.begin("atoi");

    auto i0 = t_atoi<int8>("-1");
    _logger->writeln("%i", i0);
    _test_case.assert(i0 == int8(-1), __FUNCTION__, "atoi #0");
    auto i1 = t_atoi<int8>("-129");  // int8 -128, 127
    _logger->writeln("%i", i1);
    _test_case.assert(i1 == int8(-129), __FUNCTION__, "atoi #1");
    auto i2 = t_atoi<int8>("-128");
    _logger->writeln("%i", i2);
    _test_case.assert(i2 == int8(-128), __FUNCTION__, "atoi #2");
    auto i3 = t_atoi<int16>("-129");
    _logger->writeln("%i", i3);
    _test_case.assert(i3 == int16(-129), __FUNCTION__, "atoi #3");

    try {
        auto i4 = t_atoi<uint8>("-1");
        _logger->writeln("%u", i4);
        _test_case.assert(i4 == uint8(-1), __FUNCTION__, "atoi #4");
    } catch (exception& e) {
        _test_case.test(expect_failure, __FUNCTION__, "exception code [%08x] %s", e.get_errorcode(), e.get_error_message().c_str());
    }
}

void test_htoi() {
    _test_case.begin("htoi");
    auto i1 = t_htoi<uint8>("0xff");
    _logger->writeln("%u", i1);
    _test_case.assert(i1 == uint8(0xff), __FUNCTION__, "htoi #1");
    auto i2 = t_htoi<uint8>("0x100");
    _logger->writeln("%u", i2);
    _test_case.assert(i2 == uint8(0x100), __FUNCTION__, "htoi #2");
    auto i3 = t_htoi<uint16>("0x100");
    _logger->writeln("%u", i3);
    _test_case.assert(i3 == uint16(0x100), __FUNCTION__, "htoi #3");
}

void testcase_int() {
    test_atoi();
    test_htoi();
}
