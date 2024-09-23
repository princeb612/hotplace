/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      openssl s_server -cert server.crt -key server.key -dtls1_2 -accept 9000
 *      ctrl+c
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <functional>
#include <sdk/nostd.hpp>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    std::string address;
    uint16 port;
    uint16 count;
    std::string message;

    _OPTION() : verbose(0), address("127.0.0.1"), port(9000), count(1), message("hello") {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

#define BUFFER_SIZE 1500

void client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tls_context_t* tlshandle = nullptr;
    socket_t sock = -1;
    SSL_CTX* sslctx = nullptr;
    x509cert_open_simple(x509cert_flag_dtls, &sslctx);
    transport_layer_security tls(sslctx);
    dtls_client_socket cli(&tls);
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    char buffer[BUFFER_SIZE];
    basic_stream bs;

    __try2 {
        openssl_startup();
#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif

        ret = cli.open(&sock, &addr, option.address.c_str(), option.port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = cli.connectto(sock, &tlshandle, option.address.c_str(), option.port, 1);
        _test_case.test(ret, __FUNCTION__, "connectto");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t cbsent = 0;
        for (auto i = 0; (i < option.count) && (errorcode_t::success == ret); i++) {
            ret = cli.sendto(sock, tlshandle, option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, sizeof(addr));
            if (errorcode_t::success == ret) {
                size_t cbread = 0;
                ret = cli.recvfrom(sock, tlshandle, buffer, BUFFER_SIZE, &cbread, (sockaddr*)&addr, &addrlen);
                if (errorcode_t::success == ret) {
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: %s", bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli.close(sock, tlshandle);
        SSL_CTX_free(sslctx);
#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif
        openssl_cleanup();
    }

    _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-a", "address (127.0.0.1)", [](OPTION& o, char* param) -> void { o.address = param; }).optional().preced()
              << t_cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced()
              // << t_cmdarg_t<OPTION>("-c", "count (1)", [](OPTION& o, char* param) -> void { o.count = atoi(param); }).optional().preced()
              << t_cmdarg_t<OPTION>("-m", "message", [](OPTION& o, char* param) -> void { o.message = param; }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    if (option.verbose) {
        set_trace_option(trace_option_t::trace_bt | trace_option_t::trace_except);
    }

    client();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
