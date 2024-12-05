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

return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    network_session_socket_t* session_socket = (network_session_socket_t*)data_array[0];
    byte_t* buf = (byte_t*)data_array[1];
    size_t bufsize = (size_t)data_array[2];
    network_session* session = (network_session*)data_array[3];
    sockaddr_storage_t* addr = (sockaddr_storage_t*)data_array[5];

    basic_stream bs;
    std::string message;

    switch (type) {
        case mux_dgram:
            _logger->writeln("read %d msg [%.*s]", session_socket->event_socket, (unsigned)bufsize, buf);
            // dump_memory (buf, bufsize, &bs, 16, 4);
            // std::cout << bs << std::endl;
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
    transport_layer_security* tls = nullptr;
    dtls_server_socket* tls_socket = nullptr;
    // DTLS handshake and thread-model
    //          single      multi
    // epoll    passed      N/A
    // IOCP     passed      passed
    uint16 nproc_threads = 1;
#if defined __linux__
    // [epoll] DTLS handshake only support single-thread model
#elif defined _WIN32 || defined _WIN64
    // [IOCP] GetQueuedCompletionStatus only catches information directly related to overlapped
    //        and is not interested in DTLS handshakes that do not use overlapped
    nproc_threads = 2;  // it works
#endif

    __try2 {
        // part of ssl certificate
        ret = tlscert_open(tlscert_flag_dtls, &sslctx, "server.crt", "server.key");

        // https://docs.openssl.org/1.1.1/man1/ciphers/
        // TLS 1.2
        SSL_CTX_set_cipher_list(
            sslctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-"
            "RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-"
            "AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-"
            "AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA");
        SSL_CTX_set_verify(sslctx, 0, nullptr);

        __try_new_catch(tls, new transport_layer_security(sslctx), ret, __leave2);
        __try_new_catch(tls_socket, new dtls_server_socket(tls), ret, __leave2);

        server_conf conf;
        conf.set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
            .set(netserver_config_t::serverconf_concurrent_network, nproc_threads)
            .set(netserver_config_t::serverconf_concurrent_consume, 2);

        // start server
        netserver.open(&handle_ipv4, AF_INET, port, tls_socket, &conf, consume_routine, nullptr);
        netserver.open(&handle_ipv6, AF_INET6, port, tls_socket, &conf, consume_routine, nullptr);

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

        tls_socket->release();
        tls->release();
        SSL_CTX_free(sslctx);
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
