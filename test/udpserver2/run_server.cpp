/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc    UDP server using network_server
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

    basic_stream bs;
    std::string message;

    switch (type) {
        case mux_dgram:
            _logger->writeln("read %d msg [%.*s]", session_socket->get_event_socket(), (unsigned)bufsize, buf);
            // dump_memory (buf, bufsize, &bs, 16, 4);
            // std::cout << bs << std::endl;
            session->sendto((char*)buf, bufsize, addr);
            break;
    }
    return ret;
}

return_t echo_server(void* param) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    network_server network_server;
    network_multiplexer_context_t* handle_ipv4 = nullptr;
    network_multiplexer_context_t* handle_ipv6 = nullptr;
    udp_server_socket svr_sock;
    uint16 port = option.port;

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    __try2 {
        server_conf conf;
        conf.set(netserver_config_t::serverconf_concurrent_event, 1024)  // concurrent (linux epoll concerns, windows ignore)
            .set(netserver_config_t::serverconf_concurrent_tls_accept, 1)
            .set(netserver_config_t::serverconf_concurrent_network, 2)
            .set(netserver_config_t::serverconf_concurrent_consume, 2);

        network_server.open(&handle_ipv4, AF_INET, port, &svr_sock, &conf, consumer_routine, nullptr);
        network_server.open(&handle_ipv6, AF_INET6, port, &svr_sock, &conf, consumer_routine, nullptr);

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

void run_server() {
    _test_case.begin("echo server (udp powered by network_server)");

    thread thread1(echo_server, nullptr);
    std::string result;

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}
