/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_parameterized.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 */

#include <hotplace/test/testcase/asn.1/sample.hpp>

static const char* example_parameterized = R"(
    -- Parameterized Type (Template)
    FRAME{TypeParam, INTEGER:maxSize} ::= SEQUENCE {
        header  INTEGER,
        payload TypeParam,
        length  INTEGER (0..maxSize)
    }

    -- Parameterized Type (Instantiation)
    MyPacket ::= FRAME{ OCTET STRING, 1024 }
)";

void test_parameterized1() {
    _test_case.begin("parameterized");
    //
}

void test_parameterized2() {
    _test_case.begin("parameterized");

    return_t ret = errorcode_t::success;

    parse_tree pt;
    asn1_loader loader;

    // intentionally split into several stages for testing and verification.

    // step.1
    ret = loader.load(example_parameterized, strlen(example_parameterized), &pt);
    _test_case.test(ret, __FUNCTION__, "loader");

    dump_parse_tree(&pt);

    // step.2
    asn1_build_resultset result;
    auto publisher = asn1_advisor::get_instance()->get_publisher();
    ret = publisher->build(&pt, result);
    _test_case.test(ret, __FUNCTION__, "publish");
}

void test_parameterized3() {
    // example6.asn1
    // example7.asn1
}

void testcase_parameterized() {
    test_parameterized1();
    // test_parameterized2();
    // test_parameterized3();
}
