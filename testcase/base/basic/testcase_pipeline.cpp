/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_pipeline.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

static void test_function(bool expect, std::string& path, const char* lhs, const char* rhs, const char* result_expect) {
    function_pipeline<return_t> pipeline;
    pipeline  //
        .test_parameter([&]() -> bool {
            path += "test_parameter->";
            return (nullptr != lhs && nullptr != rhs && nullptr != result_expect);
        })
        .walk([&]() -> void { path += "walk->"; })
        .run_pipe([&]() -> return_t {
            path += "run_pipe->";
            return (bignumber(result_expect) == bignumber(lhs) + bignumber(rhs)) ? errorcode_t::success : errorcode_t::unexpected;
        })
        .walk([&]() -> void { path += "walk->"; })
        .walk_failed([&]() -> void { path += "walk_failed->"; })
        .walk_always([&]() -> void { path += "end"; });
    auto ret = pipeline.result();
    if (expect) {
        _test_case.test(ret, __FUNCTION__, "check return code");
    } else {
        _test_case.ntest(ret, __FUNCTION__, "check return code");
    }
}

void test_pipeline1() {
    _test_case.begin("pipeline");
    {
        std::string path;
        test_function(false, path, nullptr, nullptr, nullptr);
        _test_case.assert(path == "test_parameter->walk_failed->end", __FUNCTION__, "case #1 %s", path.c_str());
    }
    {
        std::string path;
        test_function(true, path, "1", "2", "3");
        _test_case.assert(path == "test_parameter->walk->run_pipe->walk->end", __FUNCTION__, "case #2 %s", path.c_str());
    }
    {
        std::string path;
        test_function(false, path, "1", "2", "1");
        _test_case.assert(path == "test_parameter->walk->run_pipe->walk_failed->end", __FUNCTION__, "case #3 %s", path.c_str());
    }
}

void test_pipeline2() {
    _test_case.begin("pipeline");
    int flag = 0;
    function_pipeline<return_t> pipeline;
    pipeline.goahead_if_not_fail()
        .run_pipe([&]() -> return_t { return errorcode_t::debug; })  // not severe category
        .run_pipe([&]() -> return_t {
            flag = 1;
            return errorcode_t::success;
        });
    _test_case.assert(1 == flag, __FUNCTION__, "pipeline goahead_if_not_fail");

    auto ret = pipeline.result();
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "pipeline goahead_if_not_fail erorcode");
}

void test_pipeline3() {
    _test_case.begin("pipeline openssl");
    return_t ret = errorcode_t::success;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline                                    //
        .run_pipe([&]() -> int { return 0; })   // run
        .run_pipe([&]() -> int { return 1; });  // do not run

    if (pipeline.failed()) {
        ret = errorcode_t::expect_failure;
    } else {
        ret = errorcode_t::success;
    }
    _test_case.assert(ret != errorcode_t::success, __FUNCTION__, "failed pipeline #1 failed");

    auto rc = pipeline.result();
    _test_case.assert(error_traits<int, osslerror_category>::to_return_t(rc) == errorcode_t::error_openssl_inside, __FUNCTION__, "failed pipeline #2 result");

    ret = pipeline.result_to_return_t();
    _test_case.assert(ret == errorcode_t::error_openssl_inside, __FUNCTION__, "failed pipeline #3 result_to_return_t");
}

void test_pipeline4() {
    _test_case.begin("pipeline linux errno");

    function_pipeline<int, errno_category> pipeline;
    pipeline.run_pipe([&]() -> int { return 0; }).run_pipe([&]() -> return_t { return errorcode_t::unknown; });  // override errorcode_t::error_internal_error

    auto ret = pipeline.result_to_return_t();
    _test_case.assert(errorcode_t::unknown == ret, __FUNCTION__, "pipeline<int> return_t");
}

void testcase_pipeline() {
    test_pipeline1();
    test_pipeline2();
    test_pipeline3();
    test_pipeline4();
}
