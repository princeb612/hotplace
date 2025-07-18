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
    int debug;
    int log;
    int time;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

return_t enum_modules_handler(uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter) {
    switch (type) {
        case enum_modules_t::enum_toolhelp: {
            MODULEENTRY32* entry = (MODULEENTRY32*)data[0];
            _logger->writeln("module [%s]", entry->szExePath);
        } break;
        case enum_modules_t::enum_psapi: {
            HMODULE module_handle = (HMODULE)data[0];
            MODULEINFO* module_info = (MODULEINFO*)data[1];
            // ...
        } break;
    }
    return errorcode_t::success;
}

void test_enum_modules() {
    _test_case.begin("enum_modules");
    return_t ret = errorcode_t::success;

    ret = enum_modules(GetCurrentProcess(), enum_modules_handler, nullptr);
    _test_case.test(ret, __FUNCTION__, "enum_modules");
}

void test_trace() {
    _test_case.begin("debug_trace");
    return_t ret = errorcode_t::success;
    debug_trace_context_t* handle = nullptr;
    debug_trace dbg;
    CONTEXT rtlcontext;
    ansi_string stream;

    dbg.open(&handle);
    dbg.capture(&rtlcontext);
    ret = dbg.trace(handle, &rtlcontext, &stream);
    dbg.close(handle);

    {
        test_case_notimecheck notimecheck(_test_case);

        _logger->writeln(stream.c_str());
    }

    _test_case.test(ret, __FUNCTION__, "debug_trace");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
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

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    test_enum_modules();
    test_trace();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
