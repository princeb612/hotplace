/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   function_pipeline.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.08   Soo Han, Kim        (codename.hotplace Revision 983)
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_FUNCTIONPIPELINE__
#define __HOTPLACE_SDK_BASE_BASIC_FUNCTIONPIPELINE__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/error.hpp>

namespace hotplace {

template <typename T>
struct error_traits;

template <>
struct error_traits<return_t> {
    static bool is_success(return_t code) { return (code == success) || (code == expect_failure); }
    static bool is_not_fail(return_t code) {
        auto category = error_advisor::get_instance()->categoryof(code);
        return (error_category_severe != category);
    }
    static return_t to_return_t(return_t code) { return code; }
};

template <>
struct error_traits<int> {
    static bool is_success(int code) { return code >= 1; }
    static bool is_not_fail(int code) { return code >= 1; }
    static return_t to_return_t(return_t code) { return (code > 1) ? success : internal_error; }
};

/**
 * @refer   Gemini
 * @sample
 *          // sketch
 *          function_pipeline<return_t> fp;
 *          myclass my;
 *
 *          pipeline.test_parameter([&]() -> bool { return (nullptr != msg); })  // check parameter
 *                  .test_not_fail()                                             // if not severe error, go ahead
 *                  .walk([&]() -> void { printf("hello world"); })              // if success
 *                  .run([&]() -> return_t { return my.a(); })                   // if success
 *                  .run([&]() -> return_t { return my.b(); })                   // if success
 *                  .run([&]() -> return_t { return my.c(); })                   // if success
 *                  .walk_failed([&]() -> void { my.undo(); });                  // if failed
 *
 *          printf("%zu/%zu\n", fp.processed(), fp.size());
 *
 *          return fp.result();
 */
template <typename T = return_t>
class function_pipeline {
   public:
    enum expect_t {
        expect_success = 1,
        expect_failure = 2,
        expect_dontcare = 3,
    };
    function_pipeline() : _lastcode(success), _processed_count(0), _total_count(0) { _is_success = error_traits<T>::is_success; };

    function_pipeline& test_parameter(std::function<bool(void)> checker) {
        if (false == checker()) {
            _lastcode = invalid_parameter;
        }
        return *this;
    }
    function_pipeline& test_success(std::function<bool(return_t)> checker) {
        _is_success = checker;
        return *this;
    }
    function_pipeline& test_only_success() {
        _is_success = error_traits<T>::_is_success;
        return *this;
    }
    function_pipeline& test_not_fail() {
        _is_success = error_traits<T>::is_not_fail;
        return *this;
    }

    function_pipeline& walk(std::function<void(void)> func) {
        return runner(
            [&]() {
                func();
                return _lastcode;
            },
            false, expect_success);
    }
    function_pipeline& walk_trycatch(std::function<void(void)> func) {
        return runner(
            [&]() {
                func();
                return _lastcode;
            },
            true, expect_success);
    }
    function_pipeline& walk_failed(std::function<void(void)> func) {
        return runner(
            [&]() {
                func();
                return _lastcode;
            },
            false, expect_failure);
    }
    function_pipeline& walk_always(std::function<void(T)> func) {
        return runner(
            [&]() {
                func(_lastcode);
                return _lastcode;
            },
            false, expect_dontcare);
    }

    template <typename F>
    function_pipeline& run(F func) {
        return runner(func, false, expect_success);
    }
    template <typename F>
    function_pipeline& run_trycatch(F func) {
        return runner(func, true, expect_success);
    }
    template <typename F>
    function_pipeline& run_failed(F func) {
        return runner(func, false, expect_failure);
    }

    size_t size() const { return _total_count; }
    size_t processed() const { return _processed_count; }
    return_t result() const { return _lastcode; }

   protected:
    template <typename F>
    function_pipeline& runner(F func, bool use_trycatch, expect_t expect = expect_success) {
        ++_total_count;

        if (expect_dontcare == expect) {
        } else {
            bool expectation = (expect_success == expect) ? true : false;
            if (expectation != _is_success(_lastcode)) {
                return *this;
            }
        }

        try {
            auto rc = func();
            check_returntype(rc);
        } catch (...) {
            if (use_trycatch) {
                _lastcode = exception_caught;
            } else {
                throw exception(exception_caught);
            }
        }
        return *this;
    }

    void check_returntype(T rc) {
        if (error_traits<return_t>::is_success(rc)) {
            _lastcode = success;
            ++_processed_count;
        } else {
            _lastcode = error_traits<T>::to_return_t(rc);
        }
    }

   private:
    return_t _lastcode;
    size_t _processed_count;
    size_t _total_count;
    std::function<bool(T)> _is_success;
};

}  // namespace hotplace

#endif
