/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_valist.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_valist_sprintf() {
    _test_case.begin("valist");

    valist va;
    va << 3.141592 << "phi" << 123;

    _logger->writeln("{1} 3.141592 {2} phi {3} 123");

    // basic
    {
        const char* fmt = "value={1} value={2} value={3}";
        const char* expect = "value=3.141592 value=phi value=123";

        basic_stream bs;
        sprintf(&bs, fmt, va);

        _logger->writeln("formatter %s", fmt);
        _logger->writeln("result    %s", bs.c_str());
        _test_case.assert(0 == strcmp(expect, bs.c_str()), __FUNCTION__, "sprintf");
    }

    // concatenate
    {
        basic_stream bs;
        bs.printf("value %08x ", 0x304);
        sprintf(&bs, "{1}:{2}:{3}", va);
        _logger->writeln(bs);
        _test_case.assert(bs == "value 00000304 3.141592:phi:123", __FUNCTION__, "value 00000304 3.141592:phi:123");
    }
}

void test_valist_cpp14() {
    _test_case.begin("valist");
    ansi_string str;

#if __cplusplus >= 201402L  // c++14
    return_t ret = errorcode_t::success;
    valist val;
    make_valist(val, 1, 3.141592, "hello");
    ret = sprintf(&str, "param1 {1} param2 {2} param3 {3}", val);

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "make_list(Ts... args) and sprintf");

    valist va;
    ret = sprintf(&str, "param1 {1} param2 {2} param3 {3}", va << 1 << 3.14 << "hello");

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "sprintf");

    ret = vprintf(&str, "param1 {1} param2 {2} param3 {3}", 1, 3.141592, "hello");

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->writeln(str.c_str());
        str.clear();
    }

    _test_case.test(ret, __FUNCTION__, "vprintf (Ts... args)");
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "at least c++14 required");
#endif
}

void test_valist_stream() {
    _test_case.begin("valist");
    basic_stream bs;
    valist va;

    va << 1 << "test string";  // argc 2

    sprintf(&bs, "value1={1} value2={2}", va);  // value1=1 value2=test string
    _logger->writeln(bs);
    _test_case.assert(bs == "value1=1 value2=test string", __FUNCTION__, "sprintf #1");
    bs.clear();

    sprintf(&bs, "value1={2} value2={1}", va);  // value1=test string value2=1
    _logger->writeln(bs);
    _test_case.assert(bs == "value1=test string value2=1", __FUNCTION__, "sprintf #2");
    bs.clear();

    sprintf(&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3={3}
    _logger->writeln(bs);
    _test_case.assert(bs == "value1=test string value2=1 value3={3}", __FUNCTION__, "sprintf #3");
    bs.clear();

    va << 3.141592f;
    sprintf(&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3=3.141592
    _test_case.assert(bs == "value1=test string value2=1 value3=3.141592", __FUNCTION__, "sprintf #4");
    _logger->writeln(bs);
    bs.clear();

    sprintf(&bs, "value1={3} value2={1} value3={2}", va);  // value1=3.141592 value2=1 value3=test string
    _test_case.assert(bs == "value1=3.141592 value2=1 value3=test string", __FUNCTION__, "sprintf #5");
    _logger->writeln(bs);

    bs.resize(50);
    _logger->dump(bs);
    _test_case.assert(50 == bs.size(), __FUNCTION__, "expand");

    sprintf(&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3=3.141592
    _logger->writeln(bs);
    _logger->dump(bs);

    bs.resize(11);
    _logger->dump(bs);
    _test_case.assert(11 == bs.size(), __FUNCTION__, "shrink");

    sprintf(&bs, "value1={2} value2={1} value3={3}", va);  // value1=test string value2=1 value3=3.141592
    _logger->writeln(bs);
    _logger->dump(bs);

    bs.resize(0);
    _test_case.assert(bs.empty(), __FUNCTION__, "resize 0");

    va << std::string("hello") << basic_stream("world");
    sprintf(&bs, "{4} {5}", va);
    _logger->writeln(bs);
    _test_case.assert(bs == "hello world", __FUNCTION__, "sprintf #6");
}

void testcase_valist() {
    test_valist_sprintf();
    test_valist_cpp14();
    test_valist_stream();
}
