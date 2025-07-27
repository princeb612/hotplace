/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void whatsthis(int argc, char** argv) {
    _cmdline->parse(argc, argv);
    const OPTION& option = _cmdline->value();

    if (option.content.empty()) {
        _cmdline->help();
    } else {
        binary_t what = std::move(base16_decode(option.content));
        basic_stream diagnostic;
        cbor_reader_context_t* handle = nullptr;
        cbor_reader reader;
        reader.open(&handle);
        reader.parse(handle, what);
        reader.publish(handle, &diagnostic);
        reader.close(handle);

        basic_stream bs;
        bs << "what u want to know"
           << "\n"
           << "< " << option.content << "\n"
           << "> " << diagnostic << "\n"
           << "> dump"
           << "\n";
        dump_memory(what, &bs, 16, 2, 0, dump_notrunc);
        _logger->consoleln(bs);
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-e", "decode CBOR", [](OPTION& o, char* param) -> void { o.content = param; }).preced().optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    _logger.make_share(builder.build());

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    test_rfc7049_table4_1();
    test_rfc7049_table4_2();
    test_parse();

    _logger->flush();

    _test_case.report(5);
    whatsthis(argc, argv);
    return _test_case.result();
}
