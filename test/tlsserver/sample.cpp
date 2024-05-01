/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      how to test
 *          openssl s_client 127.0.0.1:9000
 *          ctrl + c
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;
using namespace hotplace::net;

test_case _test_case;

#define FILENAME_RUN _T (".run")
#define PORT 9000

return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    net_session_socket_t* session_socket = (net_session_socket_t*)data_array[0];
    network_session* session = (network_session*)data_array[3];
    byte_t* buf = (byte_t*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

    basic_stream bs;
    std::string message;

    switch (type) {
        case mux_connect:
            std::cout << "connect " << session_socket->cli_socket << std::endl;
            break;
        case mux_read:
            printf("read %i (%zi) %.*s\n", session_socket->cli_socket, bufsize, (unsigned)bufsize, buf);
            // dump_memory (buf, bufsize, &bs, 16, 4);
            // std::cout << bs.c_str () << std::endl;
            session->send((char*)buf, bufsize);
            break;
        case mux_disconnect:
            std::cout << "disconnect " << session_socket->cli_socket << std::endl;
            break;
    }
    return ret;
}

return_t echo_server(void*) {
    return_t ret = errorcode_t::success;
    network_server netserver;
    network_multiplexer_context_t* handle_ipv4 = nullptr;
    network_multiplexer_context_t* handle_ipv6 = nullptr;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    SSL_CTX* x509 = nullptr;
    // http_protocol* http_prot = nullptr;
    transport_layer_security* tls = nullptr;
    tls_server_socket* tls_server = nullptr;

    __try2 {
        // part of ssl certificate
        ret = x509_open(&x509, "server.crt", "server.key");
        _test_case.test(ret, __FUNCTION__, "x509");

        SSL_CTX_set_cipher_list(x509,
                                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256");
        // SSL_CTX_set_cipher_list (x509,
        // "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:AES128-GCM-SHA256:AES128-SHA256:AES256-GCM-SHA384:AES256-SHA256:!aNULL:!eNULL:!LOW:!EXP:!RC4");
        SSL_CTX_set_verify(x509, 0, nullptr);

        __try_new_catch(tls, new transport_layer_security(x509), ret, __leave2);
        //__try_new_catch (http_prot, new http_protocol, ret, __leave2);
        __try_new_catch(tls_server, new tls_server_socket(tls), ret, __leave2);

        // start server
        netserver.open(&handle_ipv4, AF_INET, IPPROTO_TCP, PORT, 1024, consume_routine, nullptr, tls_server);
        netserver.open(&handle_ipv6, AF_INET6, IPPROTO_TCP, PORT, 1024, consume_routine, nullptr, tls_server);
        // netserver.add_protocol(handle_ipv4, http_prot);

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

        // http_prot->release ();
        tls_server->release();
        tls->release();
        SSL_CTX_free(x509);
    }

    return ret;
}

void test_tlsserver() {
    thread thread1(echo_server, nullptr);
    return_t ret = errorcode_t::success;

    __try2 {
        _test_case.begin("tls server");

        thread1.start();
    }
    __finally2 { thread1.wait(-1); }
}

int main() {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    test_tlsserver();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report();
    return _test_case.result();
}
