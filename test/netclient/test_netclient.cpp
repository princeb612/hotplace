/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void tcp_client() {
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    client_socket* cli = nullptr;
    if (0 == (option.flags & option_flag_debug_tls_inside)) {
        cli = new naive_tcp_client_socket;
    } else {
        cli = new trial_tcp_client_socket;
    }

    char buffer[option.bufsize];

    __try2 {
        cli->set_wto(option.wto);

        ret = cli->connect(option.address.c_str(), option.port, option.wto / 1000);
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
                    basic_stream bs;
                    bs.write(buffer, cbread);
                    while (errorcode_t::more_data == test) {
                        test = cli->more(buffer, option.bufsize, &cbread);
                        if (errorcode_t::more_data == test) {
                            bs.write(buffer, cbread);
                        }
                    }
                    _logger->writeln("received response: [%d][len %zi]%s", cli->get_socket(), bs.size(), bs.c_str());
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
    if (0 == (option.flags & option_flag_debug_tls_inside)) {
        cli = new naive_udp_client_socket;
    } else {
        cli = new trial_udp_client_socket;
    }

    char buffer[option.bufsize];
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    __try2 {
        cli->set_wto(option.wto);

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
                    basic_stream bs;
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: [%d][len %zi]%s", cli->get_socket(), bs.size(), bs.c_str());
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
    if (option.flags & option_flag_allow_tls12) {
        tlscontext_flags |= tlscontext_flag_allow_tls12;
    }
    if (option.flags & option_flag_allow_tls13) {
        tlscontext_flags |= tlscontext_flag_allow_tls13;
    }
    tlscontext_open_simple(&sslctx, tlscontext_flags);
    openssl_tls tls(sslctx);
    openssl_tls_client_socket cli(&tls);

    char buffer[option.bufsize];

    __try2 {
        openssl_startup();

        cli.set_wto(option.wto);

        ret = cli.connect(option.address.c_str(), option.port, option.wto / 1000);
        _test_case.test(ret, __FUNCTION__, "connect");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                basic_stream bs;
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
    auto minver = (option.flags & option_flag_allow_tls12) ? tls_12 : tls_13;
    trial_tls_client_socket cli(minver);

    char buffer[option.bufsize];

    __try2 {
        openssl_startup();

        cli.set_wto(option.wto);

        ret = cli.connect(option.address.c_str(), option.port, option.wto / 1000);
        _test_case.test(ret, __FUNCTION__, "connect");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        for (auto i = 0; i < option.count; i++) {
            size_t cbsent = 0;
            auto test = cli.send(option.message.c_str(), option.message.size(), &cbsent);
            if (errorcode_t::success == test) {
                basic_stream bs;
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
    openssl_dtls_client_socket cli(&tls);
    sockaddr_storage_t addr;
    socklen_t addrlen = sizeof(addr);

    char buffer[option.bufsize];

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
                    basic_stream bs;
                    bs.write(buffer, cbread);
                    _logger->writeln("received response: [%d][len %zi]%s", cli.get_socket(), bs.size(), bs.c_str());
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
    trial_dtls_client_socket cli(dtls_12);
    cli.get_session()->get_dtls_record_publisher().set_fragment_size(512);
    cli.get_session()->get_dtls_record_publisher().set_flags(dtls_record_publisher_multi_handshakes);

    char buffer[option.bufsize];
    sockaddr_storage_t sa;

    __try2 {
        openssl_startup();

        cli.set_wto(option.wto);

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

void quic_client() {
    const OPTION& option = _cmdline->value();

    // - [ ] TODO
    //   - [ ] tls_composer QUIC feature
    //   - [ ] trial_quic_client_socket
    //   - [ ] trial_quic_server_socket
}
