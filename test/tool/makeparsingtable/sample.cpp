/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;

struct OPTION : public CMDLINEOPTION {
    std::string outfile;
    parser_type_t type;

    OPTION() : CMDLINEOPTION(), type(parser_type_t::lalr1) {}
};
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

return_t test1() {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    binary_parsing_table pt;
    if (parser_type_t::glr == option.type) {
        auto& parser = get_glr_parser_asn1_by_build();
        pt.learn(&parser);
    } else /* if (parser_type_t::lalr1 == option.type) */ {
        auto& parser = get_lalr1_parser_asn1_notation_by_build();
        pt.learn(&parser);
    }
    pt.write(option.outfile);

    return ret;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    return_t ret = errorcode_t::success;

    openssl_startup();

    __try2 {
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
            << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, const char* param) -> void { o.time = 1; }).optional()
            << t_cmdarg_t<OPTION>("-glr", "ASN.1 GLR parsing table", [](OPTION& o, const char* param) -> void { o.type = parser_type_t::glr; }).optional()
            << t_cmdarg_t<OPTION>("-o", "file", [](OPTION& o, const char* param) -> void { o.outfile = param; }).preced().optional();
        ret = _cmdline->parse(argc, argv);
        if (errorcode_t::success != ret) {
            _cmdline->help();
            __leave2;
        }

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

        if (option.outfile.empty()) {
            __leave2;
        }

        if (option.debug) {
            auto lambda_tracedebug = [&](trace_category_t category, trace_event_t event, stream_t* s) -> void { _logger->write(s); };
            set_trace_debug(lambda_tracedebug);
            set_trace_option(trace_bt | trace_except | trace_debug);
            set_trace_level(option.trace_level);
        }

        test1();
    }
    __finally2 {}

    openssl_cleanup();

    if (_logger) _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
