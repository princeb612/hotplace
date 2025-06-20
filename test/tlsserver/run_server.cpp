/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      test.1
 *          openssl s_client -tls1_3 127.0.0.1:9000
 *          ctrl + c
 *      test.2
 *          test-tlsclient
 *
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    netsocket_t* session_socket = (netsocket_t*)data_array[0];
    network_session* session = (network_session*)data_array[3];
    byte_t* buf = (byte_t*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

    basic_stream bs;
    std::string message;

    switch (type) {
        case mux_connect:
            _logger->writeln("connect %d", session_socket->get_event_socket());
            break;
        case mux_read:
            _logger->writeln("read %d msg [%.*s]", session_socket->get_event_socket(), (unsigned)bufsize, buf);
            // dump_memory (buf, bufsize, &bs, 16, 4);
            // std::cout << bs << std::endl;
            session->send((char*)buf, bufsize);
            break;
        case mux_disconnect:
            _logger->writeln("disconnect %d", session_socket->get_event_socket());
            break;
    }
    return ret;
}

return_t echo_server(void*) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    network_server netserver;
    network_multiplexer_context_t* handle_ipv4 = nullptr;
    network_multiplexer_context_t* handle_ipv6 = nullptr;
    uint16 port = option.port;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    SSL_CTX* sslctx = nullptr;
    // http_protocol* http_prot = nullptr;
    openssl_tls* tls = nullptr;
    server_socket* tls_socket = nullptr;

    __try2 {
        if (option_flag_trial & option.flags) {
            // enable TLS 1.2 TLS_ECDHE_RSA ciphersuites
            load_certificate("rsa.crt", "rsa.key", nullptr);
            // enable TLS 1.2 TLS_ECDHE_ECDSA ciphersuites
            load_certificate("ecdsa.crt", "ecdsa.key", nullptr);

            __try_new_catch(tls_socket, new trial_tls_server_socket, ret, __leave2);

            auto tlsadvisor = tls_advisor::get_instance();
            tlsadvisor->set_ciphersuites(option.cs.c_str());
        } else {
            // part of ssl certificate

            uint32 tlscontext_flags = tlscontext_flag_tls;
            std::string ciphersuites;
            if (option.flags & option_flag_allow_tls13) {
                tlscontext_flags |= tlscontext_flag_allow_tls13;
            }
            if (option.flags & option_flag_allow_tls12) {
                tlscontext_flags |= tlscontext_flag_allow_tls12;
            }

            if (option.cs.empty()) {
                ciphersuites += "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";
                ciphersuites += ":";
                ciphersuites +=
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:"
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:"
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:"
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:"
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
            } else {
                ciphersuites += option.cs;
            }

            ret = openssl_tls_context_open(&sslctx, tlscontext_flags, "rsa.crt", "rsa.key");

            SSL_CTX_set_cipher_list(sslctx, ciphersuites.c_str());

            _logger->writeln("ciphersuites %s", ciphersuites.c_str());

            SSL_CTX_set_verify(sslctx, 0, nullptr);

            __try_new_catch(tls, new openssl_tls(sslctx), ret, __leave2);
            __try_new_catch(tls_socket, new openssl_tls_server_socket(tls), ret, __leave2);
        }

        server_conf conf;
        conf.set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
            .set(netserver_config_t::serverconf_concurrent_network, 2)
            .set(netserver_config_t::serverconf_concurrent_consume, 2);

        // start server
        netserver.open(&handle_ipv4, AF_INET, port, tls_socket, &conf, consumer_routine, nullptr);
        netserver.open(&handle_ipv6, AF_INET6, port, tls_socket, &conf, consumer_routine, nullptr);

        netserver.consumer_loop_run(handle_ipv4, 2);
        netserver.consumer_loop_run(handle_ipv6, 2);
        netserver.event_loop_run(handle_ipv4, 2);
        netserver.event_loop_run(handle_ipv6, 2);

        while (true) {
            msleep(1000);

#if defined __linux__
            int chk = access(FILENAME_RUN, F_OK);
            if (errorcode_t::success != chk) {
                break;
            }
#elif defined _WIN32 || defined _WIN64
            uint32 dwAttrib = GetFileAttributes(FILENAME_RUN);
            if (INVALID_FILE_ATTRIBUTES == dwAttrib) {
                break;
            }
#endif
        }

        netserver.event_loop_break(handle_ipv4, 2);
        netserver.event_loop_break(handle_ipv6, 2);
        netserver.consumer_loop_break(handle_ipv4, 2);
        netserver.consumer_loop_break(handle_ipv6, 2);
    }
    __finally2 {
        netserver.close(handle_ipv4);
        netserver.close(handle_ipv6);

        tls_socket->release();

        if (option_flag_trial & option.flags) {
        } else {
            tls->release();
            SSL_CTX_free(sslctx);
        }
    }

    return ret;
}

void run_server() {
    thread thread1(echo_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("tls server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}
