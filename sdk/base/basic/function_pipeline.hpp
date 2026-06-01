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
 *
 *          // improvement (codename.hotplace Revision 1021)
 *          function_pipeline<int> pipeline;
 *                  .run([&]() -> int { return my.a(); })
 *                  .run([&]() -> return_t { return errorcode_t::internal_error; });  // also support
 *          return pipeline.result_to_return_t();  // return errorcode_t::internal_error
 */
template <typename T = return_t>
class function_pipeline {
   public:
    enum expect_t {
        expect_success = 1,
        expect_failure = 2,
        expect_dontcare = 3,
    };

    typedef std::function<bool(T)> discriminant_t;
    typedef std::function<void(const char*, unsigned int, T)> debug_tracer_t;

    function_pipeline() : _lastcode(error_traits<T>::value_success()), _processed_count(0), _total_count(0), _tracer(nullptr), _returncode(errorcode_t::success) {
        _discriminant = error_traits<T>::is_success;
    };
    ~function_pipeline() {
#if defined DEBUG
        if (processed() != size()) {
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_debug)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
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

    // bool(void)
    template <typename F>
    function_pipeline& test_parameter(F checker) {
        if (false == checker()) {
            _lastcode = error_traits<T>::value_invalid_parameter();
        }
        return *this;
    }
    // bool(T)
    template <typename F>
    function_pipeline& set(F checker) {
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
    function_pipeline& set_tracer(debug_tracer_t tracer) {
        _tracer = tracer;
        return *this;
    }

    template <typename F>
    function_pipeline& walk(F func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, false, expect_success);
    }
    template <typename F>
    function_pipeline& walk_trycatch(F func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, true, expect_success);
    }
    template <typename F>
    function_pipeline& walk_failed(F func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, false, expect_failure);
    }
    template <typename F>
    function_pipeline& walk_always(F func) {
        auto lambda = [&]() {
            func();
            return _lastcode;
        };
        return runner(lambda, false, expect_dontcare);
    }

    /**
     * @brief   for RELEASE
     */
    template <typename F>
    function_pipeline& run(F func) {
        return runner(func, false, expect_success);
    }

    /*
     * @brief   DEBUG only (see run_pipe macro)
     * @remarks handling both RELEASE(NDEBUG) and DEBUG, MUST use the run_pipe macro.
     */
#if defined DEBUG
#define run_pipe(lambda) run((lambda), __FILE__, __LINE__)
    template <typename F>
    function_pipeline& run(F func, const char* file, unsigned int line) {
        return runner_debug(func, false, expect_success, file, line);
    }
#else
#define run_pipe(lambda) run((lambda))
#endif

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
    return_t result_to_return_t() const { return (_returncode != errorcode_t::success) ? _returncode : error_traits<T>::to_return_t(_lastcode); }
    bool passed() const { return _discriminant(_lastcode); }
    bool failed() const { return (false == _discriminant(_lastcode)); }

   protected:
    template <typename RT, typename CT = return_t>
    struct is_return_type : std::is_same<typename std::decay<RT>::type, CT> {};

    template <typename F>
    function_pipeline& runner(F func, bool use_trycatch, expect_t expect) {
        if (expect_failure != expect) {
            ++_total_count;
        }
        if (expect_dontcare != expect) {
            bool expectation = (expect_success == expect);
            if (expectation != _discriminant(_lastcode)) {
                return *this;
            }
        }

        try {
            auto rc = func();
            // trace here in debug version
            handle_result(rc, typename is_return_type<decltype(rc), return_t>::type());
        } catch (...) {
            if (use_trycatch) {
                _lastcode = error_traits<T>::value_exception();
            } else {
                throw exception(errorcode_t::exception_caught);
            }
        }
        return *this;
    }
#if defined DEBUG
    template <typename F>
    function_pipeline& runner_debug(F func, bool use_trycatch, expect_t expect, const char* file, unsigned int line) {
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
            handle_result(rc, typename is_return_type<decltype(rc), return_t>::type(), file, line);
        } catch (...) {
            if (use_trycatch) {
                _lastcode = error_traits<T>::value_exception();
            } else {
                throw exception(errorcode_t::exception_caught);
            }
        }
        return *this;
    }
#endif
    void test_returncode(T rc) {
        _lastcode = rc;
        if (_discriminant(rc)) {
            ++_processed_count;
        }
    }

    // F -> T
    template <typename RT>
    void handle_result(RT rc, std::false_type) {
        test_returncode(rc);
    }
    // F -> return_t
    void handle_result(return_t rc, std::true_type) {
        auto code = error_traits<T>::from_return_t(rc);
        _returncode = rc;
        test_returncode(code);
    }

#if defined DEBUG
    template <typename RT>
    void handle_result(RT rc, std::false_type, const char* file, unsigned int line) {
        if ((nullptr != _tracer) && !_discriminant(rc)) {
            _tracer(file, line, rc);
        }

        test_returncode(rc);
    }
    void handle_result(return_t rc, std::true_type, const char* file, unsigned int line) {
        auto code = error_traits<T>::from_return_t(rc);
        if ((nullptr != _tracer) && !_discriminant(code)) {
            _tracer(file, line, code);
        }
        _returncode = rc;
        test_returncode(code);
    }
#endif

   private:
    T _lastcode;
    size_t _processed_count;
    size_t _total_count;
    discriminant_t _discriminant;
    debug_tracer_t _tracer;
    return_t _returncode;
};

}  // namespace hotplace

#endif
