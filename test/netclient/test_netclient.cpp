/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      simple https server implementation
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void tcp_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    client_socket* cli = nullptr;
    if (0 == (option.flags & flag_debug_tls_inside)) {
        cli = new tcp_client_socket;
    } else {
        cli = new tcp_client_socket2;
    }

    char buffer[option.bufsize];
    basic_stream bs;

    __try2 {
        ret = cli->connect(option.address.c_str(), option.port, 1);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli->send(option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli->read(buffer, option.bufsize, &cbread);
                if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli->more(buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                    _logger->writeln("received response: [%d][len %zi]%s", cli->get_socket(), bs.size(), bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli->close();
        cli->release();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void udp_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    client_socket* cli = nullptr;
    if (0 == (option.flags & flag_debug_tls_inside)) {
        cli = new udp_client_socket;
    } else {
        cli = new udp_client_socket2;
    }

    char buffer[option.bufsize];
    basic_stream bs;
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    __try2 {
        ret = cli->open(&addr, option.address.c_str(), option.port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli->sendto(option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, addrlen);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli->recvfrom(buffer, option.bufsize, &cbread, (sockaddr*)&addr, &addrlen);
                if (errorcode_t::success == test) {
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: [%d][len %zi]%s", cli->get_socket(), bs.size(), bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli->close();
        cli->release();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void tls_client() {
    const OPTION& option = _cmdline->value();

    // server TLS 1.2 cipher suites

    return_t ret = errorcode_t::success;
    SSL_CTX* sslctx = nullptr;
    uint32 tlscontext_flags = tlscontext_flag_tls;
    if (option.flags & flag_allow_tls12) {
        tlscontext_flags |= tlscontext_flag_allow_tls12;
    }
    if (option.flags & flag_allow_tls13) {
        tlscontext_flags |= tlscontext_flag_allow_tls13;
    }
    tlscontext_open_simple(&sslctx, tlscontext_flags);
    openssl_tls tls(sslctx);
    tls_client_socket cli(&tls);

    char buffer[option.bufsize];
    basic_stream bs;

    __try2 {
        openssl_startup();

        ret = cli.connect(option.address.c_str(), option.port, 1);
        _test_case.test(ret, __FUNCTION__, "connect");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.read(buffer, option.bufsize, &cbread);
                if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli.more(buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                }
                _logger->writeln("received response: [%d][len %zi]%s", cli.get_socket(), bs.size(), bs.c_str());
                // _logger->dump(bs);
                bs.clear();
            }
        }
    }
    __finally2 {
        cli.close();
        SSL_CTX_free(sslctx);
        openssl_cleanup();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void tls_client2() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    auto minver = (option.flags & flag_allow_tls12) ? tls_12 : tls_13;
    tls_client_socket2 cli(minver);

    if (option.flags & flag_enable_etm) {
        cli.get_session().get_keyvalue().set(session_enable_encrypt_then_mac, 1);
    }

    char buffer[option.bufsize];
    basic_stream bs;

    __try2 {
        openssl_startup();

        ret = cli.connect(option.address.c_str(), option.port, 1);
        _test_case.test(ret, __FUNCTION__, "connect");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.read(buffer, option.bufsize, &cbread);
                if ((errorcode_t::success == test) || (errorcode_t::more_data == test)) {
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli.more(buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                }
                _logger->writeln("received response: [%d][len %zi]%s", cli.get_socket(), bs.size(), bs.c_str());
                // _logger->dump(bs);
                bs.clear();
            }
        }
    }
    __finally2 {
        cli.close();
        openssl_cleanup();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void dtls_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    SSL_CTX* sslctx = nullptr;
    tlscontext_open_simple(&sslctx, tlscontext_flag_dtls);
    openssl_tls tls(sslctx);
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

        ret = cli.open(&addr, option.address.c_str(), option.port);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // sendto/recvfrom
        size_t cbsent = 0;
        for (auto i = 0; i < option.count; i++) {
            auto test = cli.sendto(option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&addr, sizeof(addr));
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                test = cli.recvfrom(buffer, option.bufsize, &cbread, (sockaddr*)&addr, &addrlen);
                if (errorcode_t::success == test) {
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: [%d][len %zi]%s", cli.get_socket(), bs.size(), bs.c_str());
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli.close();
        SSL_CTX_free(sslctx);
#if defined _WIN32 || defined _WIN64
        winsock_cleanup();
#endif
        openssl_cleanup();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}

void dtls_client2() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    dtls_client_socket2 cli(tls_12);

    char buffer[option.bufsize];
    basic_stream bs;
    sockaddr_storage_t sa;

    __try2 {
        openssl_startup();

        ret = cli.open(&sa, option.address.c_str(), option.port);
        _test_case.test(ret, __FUNCTION__, "open");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.sendto(option.message.c_str(), option.message.size(), &cbsent, (sockaddr*)&sa, sizeof(sa));
            if (errorcode_t::success == test) {
                size_t cbread = 0;
                sockaddr_storage_t peer;
                std::string addr;
                socklen_t addrlen = sizeof(addr);

                test = cli.recvfrom(buffer, option.bufsize, &cbread, (sockaddr*)&peer, &addrlen);

                if (success == test) {
                    sockaddr_string(peer, addr);

                    _logger->writeln("received response: [%d][len %zi]%.*s", cli.get_socket(), cbread, cbread, buffer);
                    bs.clear();
                }
            }
        }
    }
    __finally2 {
        cli.close();
        openssl_cleanup();

        _test_case.test(ret, __FUNCTION__, "client %s:%i", option.address.c_str(), option.port);
    }
}
