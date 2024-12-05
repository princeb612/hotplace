/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;
    int attach;

    _OPTION() : verbose(0), log(0), time(0), attach(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION &o, char *param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION &o, char *param) -> void { o.time = 1; }).optional()
              << t_cmdarg_t<OPTION>("-a", "attach", [](OPTION &o, char *param) -> void { o.attach = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.attach) {
        _test_case.attach(_logger);
    }

    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();
    test_convert_endian();
    test_byte_capacity_unsigned();
    test_byte_capacity_signed();
    test_maphint();
    test_binary();
    test_loglevel();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
