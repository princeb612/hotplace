/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  MINGW COM
 *      ATL-related issues (heavily MSVC-dependent)
 *          INetFwPolicy2 (Windows Firewall implementation)
 *          IWbemClassObject (WMI implementation)
 *      hard to apply CComVariant
 *          failed ... Community/VC/Tools/MSVC/14.37.32822/atlmfc/include
 *          not tested ... https://github.com/reactos/reactos/tree/master/sdk/lib/atl
 *
 *  MINGW backtrace
 *      GetSymFromAddr, SymGetLineFromAddr
 *      libbfd link error
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
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_trace() {
    _test_case.begin("debug_trace");
    return_t ret = errorcode_t::success;
    ansi_string stream;
    ret = debug_trace(&stream);
    _logger->writeln(stream.c_str());
    _test_case.test(ret, __FUNCTION__, "debug_trace");
}

int main(int argc, char** argv) {
    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    test_trace();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
