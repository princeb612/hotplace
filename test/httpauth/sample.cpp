/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

test_case _test_case;
t_shared_instance<logger> _logger;
t_shared_instance<t_cmdline_t<OPTION> > _cmdline;
t_shared_instance<http_server> _http_server;

#define FILENAME_RUN _T (".run")

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    (*_cmdline) << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
                << t_cmdarg_t<OPTION>("-d", "debug/trace", [](OPTION& o, char* param) -> void { o.debug = 1; }).optional()
                << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
                << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
                << t_cmdarg_t<OPTION>("-r", "run server", [](OPTION& o, char* param) -> void { o.run = 1; }).optional()
                << t_cmdarg_t<OPTION>("-h", "http  port (default 8080)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-s", "https port (default 9000)", [](OPTION& o, char* param) -> void { o.port_tls = atoi(param); }).preced().optional()
                << t_cmdarg_t<OPTION>("-h2", "HTTP/2", [](OPTION& o, char* param) -> void { o.h2 = 1; }).optional()
                << t_cmdarg_t<OPTION>("-k", "keylog", [](OPTION& o, char* param) -> void { o.keylog = 1; }).optional();

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
    _logger->setcolor(bold, cyan);

    if (option.debug) {
        auto lambda_tracedebug = [&](trace_category_t category, uint32 event, stream_t* s) -> void { _logger->write(s); };
        set_trace_debug(lambda_tracedebug);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    auto lambda = [&](const char* line) -> void { _logger->writeln(line); };
    if (option.keylog) {
        auto sslkeylog = sslkeylog_exporter::get_instance();
        sslkeylog->set(lambda);
    }

    if (option.run) {
#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif
        openssl_startup();

        run_server();

        openssl_cleanup();

#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif
    }

    _logger->flush();

    _test_case.report();
    _cmdline->help();
    return _test_case.result();
}
