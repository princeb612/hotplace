/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   function_pipeline.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.08   Soo Han, Kim        sketch (codename.hotplace Revision 983)
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_FUNCTIONPIPELINE__
#define __HOTPLACE_SDK_BASE_BASIC_FUNCTIONPIPELINE__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/error.hpp>
#include <hotplace/sdk/base/system/trace.hpp>

namespace hotplace {

/**
 * @refer   Gemini
 * @sample
 *          // sketch
 *          function_pipeline<return_t> pipeline;
 *          myclass my;
 *
 *          pipeline.test_parameter([&]() -> bool { return (nullptr != msg); })  // check parameter
 *                  .goahead_if_not_fail()                                       // if not severe error, go ahead
 *                  .walk([&]() -> void { printf("hello world"); })              // if success
 *                  .run([&]() -> return_t { return my.a(); })                   // if success
 *                  .run([&]() -> return_t { return my.b(); })                   // if success
 *                  .run([&]() -> return_t { return my.c(); })                   // if success
 *                  .walk_failed([&]() -> void { my.undo(); });                  // if failed
 *
 *          printf("%zu/%zu\n", pipeline.processed(), pipeline.size());
 *
 *          return pipeline.result();
 */
template <typename T = return_t>
class function_pipeline {
   public:
    enum expect_t {
        expect_success = 1,
        expect_failure = 2,
        expect_dontcare = 3,
    };
    function_pipeline() : _lastcode(error_traits<T>::value_success()), _processed_count(0), _total_count(0) { _discriminant = error_traits<T>::is_success; };
    ~function_pipeline() {
#if defined DEBUG
        if (processed() != size()) {
            if (istraceable(trace_category_internal, loglevel_debug)) {
                trace_debug_event(trace_category_internal, trace_event_internal, [&](basic_stream& dbs) -> void {
                    std::string code;
                    auto rc = error_traits<T>::to_return_t(_lastcode);
                    error_advisor::get_instance()->error_code(rc, code);

                    dbs.println("pipeline report");
                    dbs.println("- processed %zi / %zi", processed(), size());
                    dbs.println("- last error 0x%08x %s", rc, code.c_str());
                });
            }
        }
#endif
    }

    function_pipeline& test_parameter(std::function<bool(void)> checker) {
        if (false == checker()) {
            _lastcode = invalid_parameter;
        }
        return *this;
    }
    function_pipeline& set(std::function<bool(T)> checker) {
        _discriminant = checker;
        return *this;
    }
    function_pipeline& goahead_if_success() {
        _discriminant = error_traits<T>::_discriminant;
        return *this;
    }
    function_pipeline& goahead_if_not_fail() {
        _discriminant = error_traits<T>::is_not_fail;
        return *this;
    }

    function_pipeline& walk(std::function<void(void)> func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, false, expect_success);
    }
    function_pipeline& walk_trycatch(std::function<void(void)> func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, true, expect_success);
    }
    function_pipeline& walk_failed(std::function<void(void)> func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, false, expect_failure);
    }
    function_pipeline& walk_always(std::function<void(T)> func) {
        auto lambda = [&]() {
            func(_lastcode);
            return _lastcode;
        };
        return runner(lambda, false, expect_dontcare);
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
    T result() const { return _lastcode; }
    bool passed() const { return _discriminant(_lastcode); }
    bool failed() const { return (false == _discriminant(_lastcode)); }

   protected:
    template <typename F>
    function_pipeline& runner(F func, bool use_trycatch, expect_t expect = expect_success) {
        if (expect_failure != expect) {
            ++_total_count;
        }
        if (expect_dontcare == expect) {
        } else {
            bool expectation = (expect_success == expect) ? true : false;
            if (expectation != _discriminant(_lastcode)) {
                return *this;
            }
        }

        try {
            auto rc = func();
            test_returncode(rc);
        } catch (...) {
            if (use_trycatch) {
                _lastcode = error_traits<T>::value_exception();
            } else {
                throw exception(exception_caught);
            }
        }
        return *this;
    }

    void test_returncode(T rc) {
        _lastcode = rc;
        if (_discriminant(rc)) {
            ++_processed_count;
        }
    }

   private:
    T _lastcode;
    size_t _processed_count;
    size_t _total_count;
    std::function<bool(T)> _discriminant;
};

}  // namespace hotplace

#endif
