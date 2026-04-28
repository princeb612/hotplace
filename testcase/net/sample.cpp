/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/net/sample.hpp>

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline)
        << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
        << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.enable_debug(); }).optional()
        << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION& o, char* param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
        << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_trace); }).optional()
        << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION& o, char* param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
        << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
        << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
        << t_cmdarg_t<OPTION>("-c", "connect", [](OPTION& o, char* param) -> void { o.connect = 1; }).optional()
        << t_cmdarg_t<OPTION>("-p", "read stream using http_protocol", [](OPTION& o, char* param) -> void { o.mode = 1; }).optional()
        << t_cmdarg_t<OPTION>("-u", "url (default https://localhost:9000/) feat. httptest1", [](OPTION& o, char* param) -> void { o.url = param; }).preced().optional();
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
        set_trace_level(option.trace_level);
    }

    __try2 {
#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif
        openssl_startup();

        testcase_http();
        testcase_http2();
        testcase_http2_frame();

        testcase_acl();

        _test_case.reset_time();
        // RFC 7541 Appendix B. Huffman Code
        auto huffcode = http_huffman_coding::get_instance();
        _test_case.assert(true, __FUNCTION__, "check loading time of HPACK Huffman Code");
        // RFC 7541 Appendix B. Huffman Code
        // RFC 7541 Appendix A.  Static Table Definition
        encoder.make_share(new hpack_encoder);
        _test_case.assert(true, __FUNCTION__, "check loading time of HPACK");
        // and now .. test_h2 wo loading time
        // huffman codes

        testcase_huffman();
        // HPACK
        testcase_rfc7541();
        testcase_h2();

        // QPACK
        testcase_rfc9204();
        testcase_capacity();
        testcase_qpack_stream();
    }
    __finally2 {
        openssl_cleanup();
#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif
    }

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
