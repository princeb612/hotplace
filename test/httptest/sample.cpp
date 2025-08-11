/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

int main(int argc, char **argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();

    _cmdline.make_share(new t_cmdline_t<OPTION>);

    /**
     *      to test -c
     *      run first : httpauth -v
     *      and then  : httptest -c
     */
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION &o, char *param) -> void { o.enable_verbose(); }).optional()
#if defined DEBUG
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION &o, char *param) -> void { o.enable_debug(); }).optional()
                << t_cmdarg_t<OPTION>("-D", "trace level 0|2", [](OPTION &o, char *param) -> void { o.enable_trace(atoi(param)); }).optional().preced()
                << t_cmdarg_t<OPTION>("--trace", "trace level [trace]", [](OPTION &o, char *param) -> void { o.enable_trace(loglevel_trace); }).optional()
                << t_cmdarg_t<OPTION>("--debug", "trace level [debug]", [](OPTION &o, char *param) -> void { o.enable_trace(loglevel_debug); }).optional()
#endif
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION &o, char *param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION &o, char *param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-c", "connect", [](OPTION &o, char *param) -> void { o.connect = 1; }).optional()
                << t_cmdarg_t<OPTION>("-p", "read stream using http_protocol", [](OPTION &o, char *param) -> void { o.mode = 1; }).optional()
                << t_cmdarg_t<OPTION>("-u", "url (default https://localhost:9000/) feat. httpauth", [](OPTION &o, char *param) -> void { o.url = param; })
                       .preced()
                       .optional();

    _cmdline->parse(argc, argv);
    const OPTION &option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log").attach(&_test_case);
    }
    _logger.make_share(builder.build());
    _logger->setcolor(bold, cyan);

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t *s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
        set_trace_level(option.trace_level);
    }

    // uri
    test_uri();
    test_uri_form_encoded_body_parameter();
    test_uri2();
    test_escape_url();

    // request
    test_request();

    // response
    test_response_compose();
    test_response_parse();

    // authenticate
    test_basic_authentication();
    test_digest_access_authentication();
    test_digest_access_authentication("MD5");
    test_digest_access_authentication("MD5-sess");
    test_digest_access_authentication("SHA-256");
    test_digest_access_authentication("SHA-256-sess");
    test_digest_access_authentication("SHA-512-256");
    test_digest_access_authentication("SHA-512-256-sess");

    test_rfc_digest_example();

    // documents
    test_documents();

    // network test
    if (option.connect) {
        // how to test
        // terminal 1
        //   cd hotplace
        //   ./make.sh debug pch
        //   cd build/test/httpauth
        //   ./test-httpauth -d
        // terminal 2
        //   cd build/test/htttest
        //   ./test-httptest -d -c
        test_get_tlsclient();
        test_get_httpclient();

        test_bearer_token();
    }

    test_http2_frame();
    test_http2();

    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
