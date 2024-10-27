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

#include <algorithm>
#include <functional>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int bufsize;
    std::string address;
    uint16 port;
    uint16 prot;
    uint16 count;
    std::string message;

    _OPTION() : verbose(0), bufsize(1500), address("127.0.0.1"), port(9000), prot(0), count(1), message("hello") {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void tcp_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tcp_client_socket cli;
    socket_t sock = -1;
    char buffer[option.bufsize];
    basic_stream bs;

    __try2 {
        ret = cli.connect(&sock, nullptr, option.address.c_str(), option.port, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(sock, nullptr, option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.read(sock, nullptr, buffer, option.bufsize, &cbread);
                if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli.more(sock, nullptr, buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                    _logger->writeln("received response: %s", bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli.close(sock, nullptr);

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void udp_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    udp_client_socket cli;
    socket_t sock = -1;
    char buffer[option.bufsize];
    basic_stream bs;
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    __try2 {
        ret = cli.open(&sock, &addr, option.address.c_str(), option.port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.sendto(sock, nullptr, option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, addrlen);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.recvfrom(sock, nullptr, buffer, option.bufsize, &cbread, (sockaddr*)&addr, &addrlen);
                if (errorcode_t::success == test) {
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: %s", bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli.close(sock, nullptr);

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void tls_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tls_context_t* tlshandle = nullptr;
    socket_t sock = -1;
    SSL_CTX* sslctx = nullptr;
    tlscert_open_simple(tlscert_flag_tls, &sslctx);
    transport_layer_security tls(sslctx);
    tls_client_socket cli(&tls);

    char buffer[option.bufsize];
    basic_stream bs;

    __try2 {
        openssl_startup();

        ret = cli.connect(&sock, &tlshandle, option.address.c_str(), option.port, 1);
        _test_case.test(ret, __FUNCTION__, "connect");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(sock, tlshandle, option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.read(sock, tlshandle, buffer, option.bufsize, &cbread);
                if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli.more(sock, tlshandle, buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                }
                _logger->dump(bs);
                bs.clear();
            }
        }
    }
    __finally2 {
        cli.close(sock, tlshandle);
        SSL_CTX_free(sslctx);
        openssl_cleanup();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void dtls_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    tls_context_t* tlshandle = nullptr;
    socket_t sock = -1;
    SSL_CTX* sslctx = nullptr;
    tlscert_open_simple(tlscert_flag_dtls, &sslctx);
    transport_layer_security tls(sslctx);
    dtls_client_socket cli(&tls);
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    char buffer[option.bufsize];
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

        // SSL_connect
        ret = cli.connectto(sock, &tlshandle, option.address.c_str(), option.port, 1);
        _test_case.test(ret, __FUNCTION__, "connectto");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // sendto/recvfrom
        size_t cbsent = 0;
        for (auto i = 0; i < option.count; i++) {
            auto test = cli.sendto(sock, tlshandle, option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, sizeof(addr));
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.recvfrom(sock, tlshandle, buffer, option.bufsize, &cbread, (sockaddr*)&addr, &addrlen);
                if (errorcode_t::success == test) {
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

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

uint16 toprot(const char* source) {
    int type = 1;               // 1 tcp, 2 udp, 3 tls, 4 dtls
    std::string text = source;  // source not nullptr
    std::transform(text.begin(), text.end(), text.begin(), tolower);
    if (("tcp" == text) || ("1" == text)) {
        type = 1;
    } else if (("udp" == text) || ("2" == text)) {
        type = 2;
    } else if (("tls" == text) || ("3" == text)) {
        type = 3;
    } else if (("dtls" == text) || ("4" == text)) {
        type = 4;
    }
    return type;
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-b", "bufsize (1500)", [](OPTION& o, char* param) -> void { o.bufsize = atoi(param); }).optional().preced()
              << t_cmdarg_t<OPTION>("-a", "address (127.0.0.1)", [](OPTION& o, char* param) -> void { o.address = param; }).optional().preced()
              << t_cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced()
              << t_cmdarg_t<OPTION>("-t", "protocol 1|2|3|4 (1 tcp, 2 udp, 3 tls, 4 dtls)", [](OPTION& o, char* param) -> void { o.prot = toprot(param); })
                     .optional()
                     .preced()
              << t_cmdarg_t<OPTION>("-c", "count (1)", [](OPTION& o, char* param) -> void { o.count = atoi(param); }).optional().preced()
              << t_cmdarg_t<OPTION>("-m", "message", [](OPTION& o, char* param) -> void { o.message = param; }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose).set(logger_t::logger_flush_time, 0).set(logger_t::logger_flush_size, 0);
    _logger.make_share(builder.build());

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif

    switch (option.prot) {
        case 2:
            udp_client();
            break;
        case 3:
            tls_client();
            break;
        case 4:
            dtls_client();
            break;
        case 1:
        default:
            tcp_client();
            break;
    }

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
