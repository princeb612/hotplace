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

    _test_case.test(ret, __FUNCTION__, "make_list and sprintf");

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

    _test_case.test(ret, __FUNCTION__, "vprintf");
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

void test_valist_formatstring() {
    _test_case.begin("valist");

    struct testvector {
        const char* fmt;
        const char* expect;
    } table[] = {
        {R"(value={1}, value={1:04x}, value={1:04d})", R"(value=256, value=0x0100, value=0256)"},
        {R"(value="{2}", value="{2:-15s}", value="{2:15s}")", R"(value="hello world", value="hello world    ", value="    hello world")"},
        {R"(value={3}, value={3:le}, value={3:lg})", R"(value=3.141592, value=3.141592e+00, value=3.14159)"},
        /**
         * {n} n must be in 1..arg so {-1} is ignored
         * {2} is a string so 10d is ignored
         * {3} is an integer so s is ignored.
         */
        {R"(value={-1}, value="{2:10d}", value={3:s})", R"(value={-1}, value="hello world", value=3.141592)"},
    };

    basic_stream bs;
    valist va;
    va << 256 << "hello world" << 3.141592;

    auto lambda_test = [&](const char* fmt, const char* expect) -> void {
        bs.clear();
        sprintf(&bs, fmt, va);
        _logger->writeln(bs);
        _test_case.assert(bs == expect, __FUNCTION__, "expect %s", expect);
    };

    for (auto item : table) {
        lambda_test(item.fmt, item.expect);
    }
}

void test_valist_binary() {
    _test_case.begin("valist");

    binary_t bin;
    valist va;
    basic_stream bs;

    for (auto i = 0; i < 128; i++) {
        bin.push_back(i);
    }

    va << bin;
    bs.vaprintf("{1:s}", va);  // the format specifier 's' in TYPE_BINARY, it outputs a character if it is printable, and '.' otherwise.
    _logger->writeln(bs);

    const char* expect = R"(................................ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~.)";
    _test_case.assert(bs == expect, __FUNCTION__, "valist binary (printable data)");

    bs.clear();

    bs.vaprintf("{1:x}", va);
    _logger->writeln(bs);
    const char* expect2 =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";
    _test_case.assert(bs == expect2, __FUNCTION__, "valist base16");
}

void test_valist_empty() {
    _test_case.begin("valist");
    basic_stream dbs;
    binary_t bin;
    valist va;
    va << bin;

    // basically treat binary as pointer
    // base16_decode(empty) return ""
    dbs.vaprintf("{1:x}", va);
    _test_case.assert(dbs.empty(), __FUNCTION__, "empty binary");
}

void testcase_valist() {
    test_valist_sprintf();
    test_valist_cpp14();
    test_valist_stream();
    test_valist_formatstring();
    test_valist_binary();
    test_valist_empty();
}
