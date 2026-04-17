/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/base/sample.hpp>

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;
std::list<std::function<void(void)>> _cases;

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION &o, char *param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION &o, char *param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION &o, char *param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION &o, char *param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION &o, char *param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION &o, char *param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-a", "attach", [](OPTION &o, char *param) -> void { o.attach = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION &option = _cmdline->value();

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
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t *s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    if (option.attach) {
        _test_case.attach(_logger);
    }

    testcase_binary();
    testcase_cmdline();
    testcase_dumpmemory();
    testcase_valist();
    testcase_variant();

    testcase_graph();

    testcase_avltree();
    testcase_btree();
    testcase_exception();
    testcase_findlte();
    testcase_list();
    testcase_map();
    testcase_ovl();
    testcase_pq();
    testcase_range();
    testcase_vector();

    testcase_aho_corasick();
    testcase_aho_corasick_wildcard();
    testcase_kmp();
    testcase_suffixtree();
    testcase_trie();
    testcase_ukkonen();
    testcase_wildcard();

    testcase_bufferio();
    testcase_stream();

    testcase_string();

    testcase_bignumber();
    testcase_capacity();
    testcase_datetime();
    testcase_endian();
    testcase_ieee754();
    testcase_shared();
    testcase_signalwait_threads();

    testcase_consolecolor();
    testcase_loglevel();
    testcase_unittest();

    for (auto testfunc : _cases) {
        testfunc();
    }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
