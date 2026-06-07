/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;

struct OPTION : public CMDLINEOPTION {};
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline)
        << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, const char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
        << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, const char* param) -> void { o.enable_debug(); }).optional()
        << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, const char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
        << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, const char* param) -> void { o.enable_trace(loglevel_t::loglevel_trace); }).optional()
        << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, const char* param) -> void { o.enable_trace(loglevel_t::loglevel_debug); }).optional()
#endif
        << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, const char* param) -> void { o.log = 1; }).optional()
        << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, const char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());
    _logger->setcolor(bold, cyan);

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, trace_event_t event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    testcase_asn1();
    testcase_parser();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
