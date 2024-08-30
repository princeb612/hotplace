/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
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
    std::string message;

    _OPTION() : verbose(0), address("127.0.0.1"), port(9000), message("hello") {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

#define BUFFER_SIZE 32

void client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tls_context_t* tlshandle = nullptr;
    socket_t sock = -1;
    SSL_CTX* x509 = nullptr;
    x509_open_simple(x509cert_flag_tls, &x509);
    transport_layer_security tls(x509);
    tls_client_socket cli(&tls);

    char buffer[BUFFER_SIZE];
    basic_stream bs;

    __try2 {
        openssl_startup();
#if defined _WIN32 || defined _WIN64
        winsock_startup();
#endif

        ret = cli.connect(&sock, &tlshandle, option.address.c_str(), option.port, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t cbsent = 0;
        ret = cli.send(sock, tlshandle, option.message.c_str(), option.message.size(), &cbsent);
        if (errorcode_t::success == ret) {
            return_t ret_read = errorcode_t::success;
            size_t cbread = 0;
            ret_read = cli.read(sock, tlshandle, buffer, BUFFER_SIZE, &cbread);
            bs.write(buffer, cbread);
            while (errorcode_t::more_data == ret_read) {
                ret_read = cli.more(sock, tlshandle, buffer, BUFFER_SIZE, &cbread);
                bs.write(buffer, cbread);
            }

            _logger->writeln("received response: %s", bs.c_str());
        }
    }
    __finally2 {
        cli.close(sock, tlshandle);
        SSL_CTX_free(x509);
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
              << t_cmdarg_t<OPTION>("-m", "message", [](OPTION& o, char* param) -> void { o.message = param; }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

    client();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
