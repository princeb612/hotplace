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
#include <hotplace/sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

uint16 toprot(OPTION& o, const char* source) {
    int type = 0;               // 1 tcp, 2 udp, 3 tls, 4 dtls, 5 quic
    std::string text = source;  // source not nullptr
    std::transform(text.begin(), text.end(), text.begin(), tolower);
    if (("tcp" == text) || ("1" == text)) {
        type = netclient_scheme_tcp;
    } else if (("udp" == text) || ("2" == text)) {
        type = netclient_scheme_udp;
    } else if (("tls" == text) || ("3" == text)) {
        type = netclient_scheme_tls;
    } else if ("tls13" == text) {
        type = netclient_scheme_tls;
        o.flags |= option_flag_allow_tls13;
    } else if ("tls12" == text) {
        type = netclient_scheme_tls;
        o.flags |= option_flag_allow_tls12;
    } else if (("dtls" == text) || ("4" == text)) {
        type = netclient_scheme_dtls;
    } else if ("quic" == text) {
        type = netclient_scheme_quic;
    }
    return type;
}

int main(int argc, char** argv) {
    return_t ret = errorcode_t::success;
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
        << t_cmdarg_t<OPTION>("-b", "bufsize (1500)", [](OPTION& o, char* param) -> void { o.bufsize = atoi(param); }).optional().preced()
        << t_cmdarg_t<OPTION>("-a", "address (127.0.0.1)", [](OPTION& o, char* param) -> void { o.address = param; }).optional().preced()
        << t_cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced()
        << t_cmdarg_t<OPTION>("-P", "protocol tcp|udp|tls|tls13|tls12|dtls|quic (1 tcp, 2 udp, 3 tls, 4 dtls, 5 quic)",
                              [](OPTION& o, char* param) -> void { o.prot = toprot(o, param); })
               .preced()
        << t_cmdarg_t<OPTION>("-c", "count (1)", [](OPTION& o, char* param) -> void { o.count = atoi(param); }).optional().preced()
        << t_cmdarg_t<OPTION>("-wto", "wait time out (1000 milli-seconds)", [](OPTION& o, char* param) -> void { o.wto = atoi(param); }).optional().preced()
        << t_cmdarg_t<OPTION>("-k", "keylog", [](OPTION& o, char* param) -> void { o.flags |= option_flag_keylog; }).optional()
        << t_cmdarg_t<OPTION>("-T", "use trial", [](OPTION& o, char* param) -> void { o.flags |= option_flag_debug_tls_inside; }).optional()
        << t_cmdarg_t<OPTION>("-h", "HTTP/1.1",
                              [](OPTION& o, char* param) -> void {
                                  o.flags |= option_flag_http;
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
            set_trace_level(option.trace_level);
        }

        auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
        if (option_flag_keylog & option.flags) {
            auto sslkeylog = sslkeylog_exporter::get_instance();
            sslkeylog->set(lambda);
        }

#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif

        switch (option.prot) {
            case netclient_scheme_tcp:
                tcp_client();
                break;
            case netclient_scheme_udp:
                udp_client();
                break;
            case netclient_scheme_tls:
                if (0 == (option.flags & option_flag_debug_tls_inside)) {
                    tls_client();
                } else {
                    tls_client2();
                }
                break;
            case netclient_scheme_dtls:
                if (0 == (option.flags & option_flag_debug_tls_inside)) {
                    dtls_client();
                } else {
                    dtls_client2();
                }
                break;
            case netclient_scheme_quic:
                quic_client();
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
