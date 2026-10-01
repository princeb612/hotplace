/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_loader.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include <hotplace/test/testcase/asn.1/sample.hpp>

void test_asn1loader_babystep() {
    _test_case.begin("loader - example1.asn1");

    const char* testfile = "example1.asn1";
    return_t ret = errorcode_t::success;

    asn1_loader loader;
    // ret = loader.load_file(testfile);
    // _test_case.test(ret, __FUNCTION__, "loader %s", testfile);
}

void testcase_loader() { test_asn1loader_babystep(); }
