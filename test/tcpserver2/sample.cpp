/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver
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

ipaddr_acl acl;

return_t accept_handler(socket_t socket, sockaddr_storage_t* client_addr, CALLBACK_CONTROL* control, void* parameter) {
    return_t ret = errorcode_t::success;
    bool result = false;

    acl.determine(client_addr, result);
    if (control) {
        *control = result ? CONTINUE_CONTROL : STOP_CONTROL;
    }
    return ret;
}

return_t network_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    return_t ret = errorcode_t::success;
    net_session_socket_t* network_session = (net_session_socket_t*)data_array[0];
    char* buf = (char*)data_array[1];
    size_t bufsize = (size_t)data_array[2];

    switch (type) {
        case multiplexer_event_type_t::mux_connect:
            std::cout << "connect " << network_session->client_socket << std::endl;
            break;
        case multiplexer_event_type_t::mux_read:
            std::cout << "read " << network_session->client_socket << " msg [" << std::string(buf, bufsize).c_str() << "]" << std::endl;
            send((socket_t)network_session->client_socket, buf, bufsize, 0);
            break;
        case multiplexer_event_type_t::mux_disconnect:
            std::cout << "disconnect " << network_session->client_socket << std::endl;
            break;
    }
    return ret;
}

return_t echo_server(void* param) {
    return_t ret = errorcode_t::success;
    network_server network_server;
    void* handle_ipv4 = nullptr;
    void* handle_ipv6 = nullptr;
    server_socket svr_sock;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    __try2 {
        acl.add_rule("127.0.0.1", true);
        acl.add_rule("::1", true);
        acl.setmode(ipaddr_acl_t::whitelist);

        network_server.open(&handle_ipv4, AF_INET, IPPROTO_TCP, PORT, 32000, network_routine, nullptr, &svr_sock);
        network_server.open(&handle_ipv6, AF_INET6, IPPROTO_TCP, PORT, 32000, network_routine, nullptr, &svr_sock);

        network_server.set_accept_control_handler(handle_ipv4, accept_handler);
        network_server.set_accept_control_handler(handle_ipv6, accept_handler);

        network_server.consumer_loop_run(handle_ipv4, 2);
        network_server.consumer_loop_run(handle_ipv6, 2);
        network_server.event_loop_run(handle_ipv4, 1);
        network_server.event_loop_run(handle_ipv6, 1);

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

        network_server.event_loop_break(handle_ipv4, 1);
        network_server.event_loop_break(handle_ipv6, 1);
        network_server.consumer_loop_break(handle_ipv4, 2);
        network_server.consumer_loop_break(handle_ipv6, 2);
    }
    __finally2 {
        network_server.close(handle_ipv4);
        network_server.close(handle_ipv6);
    }

    return ret;
}

void test1() {
    _test_case.begin("echo server");

    thread thread1(echo_server, nullptr);
    std::string result;

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}

int main() {
#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();
    openssl_thread_setup();

    test1();

    openssl_thread_end();
    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _test_case.report();
    return _test_case.result();
}
