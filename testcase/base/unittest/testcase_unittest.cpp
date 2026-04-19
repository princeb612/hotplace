/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

void test_testcase() {
    _test_case.begin("test_case");
    _test_case.test(errorcode_t::success, "function1", "case desc 1");  // pass
    // _test_case.test(errorcode_t::invalid_parameter, "function2", "case desc 2 - intentional fail");  // fail
    _test_case.test(errorcode_t::not_supported, "function3", "case desc 4");  // skip
    _test_case.test(errorcode_t::low_security, "function4", "case desc 5");   // low

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->consoleln("pause, resume and estimate time");
        msleep(1000);
    }

    _test_case.test(errorcode_t::success, "function5", "case 1 desc 1");  // pass
    // _test_case.test(errorcode_t::failed, "function6", "case 1 desc 2 - intentional fail");  // fail

    _test_case.test(errorcode_t::success, "function7", "case 2 desc 1");  // pass
    _test_case.assert(true, "function8", "case 2 desc 2");                // pass
    // _test_case.assert(false, "function9", "case 2 desc 3 - intentional fail");  // fail

    const char* msg1 = "MSVC variable arguments ambiguity problem";
    _test_case.assert(true, "function10", "case 3 %s", msg1 ? msg1 : "");

    // return_t ret = _test_case.result();
    // _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "result");
}

return_t function_always_fail() { return errorcode_t::internal_error; }

void test_fail() {
    _test_case.begin("test_case");
    return_t ret = errorcode_t::success;
    int test = 0;
    __try2 {
        ret = function_always_fail();
        __leave2_if_fail(ret);

        test = 1;
    }
    __finally2 { _test_case.assert(0 == test, __FUNCTION__, "__leave2_if_fail"); }
}

void test_trace() {
    _test_case.begin("test_case");
    return_t ret = errorcode_t::success;
    __try2 {
        ret = function_always_fail();
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);  // PDB
        }
    }
    __finally2 { _test_case.assert(true, __FUNCTION__, "__leave2_trace"); }
}

void test_try_leave() {
    _test_case.begin("test_case");
    return_t ret = errorcode_t::success;

    __try2 {
        ret = function_always_fail();
        if (errorcode_t::success != ret) {
            __leave2_tracef(ret, "%s %f %d %s", "debugging formatted message here", 3.14, 3, "phi");
        }
    }
    __finally2 { _test_case.assert(true, __FUNCTION__, "__leave2_tracef"); }
}

void test_error() {
    _test_case.begin("test_case");
    error_advisor* advisor = error_advisor::get_instance();
    std::string code;
    std::string message;
    return_t ret = errorcode_t::invalid_parameter;
    advisor->error_code(ret, code);
    advisor->error_message(ret, message);
    _logger->writeln("code    %08x %s", ret, code.c_str());
    _logger->writeln("message %08x %s", ret, message.c_str());
}

void test_except() {
    _test_case.begin("test_case");
    int* pointer = nullptr;
    *pointer = 1;
}

void testcase_unittest() {
    test_testcase();
    test_fail();
    test_trace();
    test_try_leave();
    test_error();
}
