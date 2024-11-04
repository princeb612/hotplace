/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;

    _OPTION() : verbose(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_unittest() {
    _test_case.begin("");

    _test_case.test(errorcode_t::success, "function1", "case desc 1");                               // pass
    _test_case.test(errorcode_t::invalid_parameter, "function2", "case desc 2 - intentional fail");  // fail
    _test_case.test(errorcode_t::not_supported, "function3", "case desc 4");                         // skip
    _test_case.test(errorcode_t::low_security, "function4", "case desc 5");                          // low

    _test_case.begin("test case 1");

    {
        test_case_notimecheck notimecheck(_test_case);
        _logger->consoleln("pause, resume and estimate time");
        msleep(1000);
    }

    _test_case.test(errorcode_t::success, "function5", "case 1 desc 1");                    // pass
    _test_case.test(errorcode_t::failed, "function6", "case 1 desc 2 - intentional fail");  // fail

    _test_case.begin("test case 2");
    _test_case.test(errorcode_t::success, "function7", "case 2 desc 1");        // pass
    _test_case.assert(true, "function8", "case 2 desc 2");                      // pass
    _test_case.assert(false, "function9", "case 2 desc 3 - intentional fail");  // fail

    return_t ret = _test_case.result();
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "result");
}

return_t function_always_fail() { return errorcode_t::internal_error; }

void test_fail() {
    _test_case.begin("try finally");
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
    _test_case.begin("try finally");
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
    _test_case.begin("error");
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
    _test_case.begin("segment fault");
    int* pointer = nullptr;
    *pointer = 1;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose)
        .set(logger_t::logger_flush_time, 0)
        .set(logger_t::logger_flush_size, 0)
        .set_timeformat("[Y-M-D h:m:s.f]")
        .set_logfile("log");
    _logger.make_share(builder.build());
    _test_case.attach(&*_logger);

    test_unittest();
    test_fail();

    set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    test_trace();
    test_try_leave();
    test_error();
    // test_except ();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return errorcode_t::success;  // return _test_case.result ();
}
