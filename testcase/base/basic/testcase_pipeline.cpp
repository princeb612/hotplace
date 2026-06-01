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
    return_t ret = errorcode_t::success;

    function_pipeline<int> pipeline;
    pipeline                                    //
        .run_pipe([&]() -> int { return 0; })   // run
        .run_pipe([&]() -> int { return 1; });  // do not run

    if (pipeline.failed()) {
        ret = errorcode_t::expect_failure;
    } else {
        ret = errorcode_t::success;
    }
    _test_case.assert(ret != errorcode_t::success, __FUNCTION__, "failed pipeline #1");

    ret = pipeline.result_to_return_t();
    _test_case.ntest(ret, __FUNCTION__, "failed pipeline #2");
}

void testcase_pipeline() {
    test_pipeline1();
    test_pipeline2();
}
