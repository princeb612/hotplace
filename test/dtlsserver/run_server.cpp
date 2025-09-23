/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc    DTLS server using network_server
 *          openssl s_client -dtls1_2 -connect 127.0.0.1:9000
 * @sa      See in the following order : udpserver1, udpserver2, dtlsserver
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

#define FILENAME_RUN _T (".run")

return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    netsocket_t* session_socket = (netsocket_t*)data_array[0];
    byte_t* buf = (byte_t*)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session* session = (network_session*)data_array[3];
    sockaddr_storage_t* addr = (sockaddr_storage_t*)data_array[5];

    std::string address;

    switch (type) {
        case mux_dgram:
            sockaddr_string(*addr, address);
            _logger->writeln("read %d [%s] msg [%.*s]", session_socket->get_event_socket(), address.c_str(), (unsigned)bufsize, buf);
            _logger->dump(buf, bufsize, 16, 4);
            session->sendto(buf, bufsize, addr);
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
    openssl_tls* tls = nullptr;
    server_socket* dtls_socket = nullptr;
    uint16 nproc_threads = 1;
#if defined __linux__
#elif defined _WIN32 || defined _WIN64
    // nproc_threads = 2;
#endif
    __try2 {
        uint32 flags = socket_scheme_dtls | socket_scheme_tls12;  // DTLS 1.2
        if (option_flag_trial & option.flags) {
            // enable TLS 1.2 TLS_ECDHE_RSA ciphersuites
            load_certificate("rsa.crt", "rsa.key", nullptr);
            // enable TLS 1.2 TLS_ECDHE_ECDSA ciphersuites
            load_certificate("ecdsa.crt", "ecdsa.key", nullptr);

            flags |= socket_scheme_trial;
        } else {
            flags |= socket_scheme_openssl;
        }

        {
            std::string ciphersuites;
            if (option.cs.empty()) {
                ciphersuites =
                    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:"
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:"
                    "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:"
                    "ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:"
                    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA";
            } else {
                ciphersuites = option.cs;
            }

            server_socket_builder builder;
            dtls_socket = builder.set(flags).set_certificate("server.crt", "server.key").set_ciphersuites(ciphersuites).set_verify(0).build();
        }

        server_conf conf;
        conf.set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
            .set(netserver_config_t::serverconf_concurrent_network, nproc_threads)
            .set(netserver_config_t::serverconf_concurrent_consume, 2);

        // start server
        netserver.open(&handle_ipv4, AF_INET, port, dtls_socket, &conf, consumer_routine, nullptr);
        netserver.open(&handle_ipv6, AF_INET6, port, dtls_socket, &conf, consumer_routine, nullptr);

        netserver.consumer_loop_run(handle_ipv4, 2);
        netserver.consumer_loop_run(handle_ipv6, 2);
        netserver.event_loop_run(handle_ipv4, nproc_threads);
        netserver.event_loop_run(handle_ipv6, nproc_threads);

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

        netserver.event_loop_break(handle_ipv4, nproc_threads);
        netserver.event_loop_break(handle_ipv6, nproc_threads);
        netserver.consumer_loop_break(handle_ipv4, 2);
        netserver.consumer_loop_break(handle_ipv6, 2);
    }
    __finally2 {
        netserver.close(handle_ipv4);
        netserver.close(handle_ipv6);

        dtls_socket->release();
    }

    return ret;
}

void run_server() {
    thread thread1(echo_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("dtls server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}
