/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      openssl s_server -cert server.crt -key server.key -tls1_3 -accept 9000
 *      openssl s_server -cert server.crt -key server.key -dtls1_2 -accept 9000
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

#include <algorithm>
#include <functional>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

uint16 toprot(OPTION& o, const char* source) {
    int type = 1;               // 1 tcp, 2 udp, 3 tls, 4 dtls
    std::string text = source;  // source not nullptr
    std::transform(text.begin(), text.end(), text.begin(), tolower);
    if (("tcp" == text) || ("1" == text)) {
        type = 1;
    } else if (("udp" == text) || ("2" == text)) {
        type = 2;
    } else if (("tls" == text) || ("3" == text)) {
        type = 3;
    } else if ("tls13" == text) {
        type = 3;
        o.flags |= flag_allow_tls13;
    } else if ("tls12" == text) {
        type = 3;
        o.flags |= flag_allow_tls12;
    } else if (("dtls" == text) || ("4" == text)) {
        type = 4;
    }
    return type;
}

int main(int argc, char** argv) {
    return_t ret = errorcode_t::success;
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log file", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-b", "bufsize (1500)", [](OPTION& o, char* param) -> void { o.bufsize = atoi(param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-a", "address (127.0.0.1)", [](OPTION& o, char* param) -> void { o.address = param; }).optional().preced()
                << t_cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-P", "protocol tcp|udp|tls|tls13|tls12|dtls (1 tcp, 2 udp, 3 tls, 4 dtls)",
                                      [](OPTION& o, char* param) -> void { o.prot = toprot(o, param); })
                       .preced()
                << t_cmdarg_t<OPTION>("-c", "count (1)", [](OPTION& o, char* param) -> void { o.count = atoi(param); }).optional().preced()
                << t_cmdarg_t<OPTION>("-A", "async", [](OPTION& o, char* param) -> void { o.flags |= flag_async; }).optional()
                << t_cmdarg_t<OPTION>("-h", "HTTP/1.1",
                                      [](OPTION& o, char* param) -> void {
                                          o.flags |= flag_http;
                                          o.message = "GET / HTTP/1.1\r\n\r\n";
                                      })
                       .optional()
                << t_cmdarg_t<OPTION>("-m", "message", [](OPTION& o, char* param) -> void { o.message = param; }).optional().preced();
    ret = _cmdline->parse(argc, argv);
    if (errorcode_t::success == ret) {
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

#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif

        switch (option.prot) {
            case 1:
                tcp_client();
                break;
            case 2:
                udp_client();
                break;
            case 3:
                if (0 == (option.flags & flag_async)) {
                    tls_client();
                } else {
                    async_tls_client();
                }
                break;
            case 4:
                if (0 == (option.flags & flag_async)) {
                    dtls_client();
                } else {
                    async_dtls_client();
                }
                break;
            default:
                break;
        }

#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif

        _logger->flush();
    }

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
