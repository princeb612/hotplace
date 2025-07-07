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

void test_maphint() {
    _test_case.begin("t_maphint");
    return_t ret = errorcode_t::success;

    std::map<int, std::string> source;
    t_maphint<int, std::string> hint(source);

    source[1] = "one";
    source[2] = "two";
    source[3] = "three";
    std::string value;
    hint.find(1, &value);
    _test_case.assert("one" == value, __FUNCTION__, "t_maphint.find(1)");
    ret = hint.find(10, &value);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "t_maphint.find(10)");

    t_maphint_const<int, std::string> hint_const(source);
    hint_const.find(2, &value);
    _test_case.assert("two" == value, __FUNCTION__, "t_maphint.find(2)");
}
