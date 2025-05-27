/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc    UDP server using multiplexer
 *          only support IPv4
 * @sa      See in the following order : udpserver, udpserver2, dtlsserver
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

#define BUFSIZE (1 << 16)
#define FILENAME_RUN _T (".run")

struct accept_context_t {
    multiplexer_context_t* mplex_handle;
    socket_t udp_server_sock;
};

/* windows */
struct netsocket_event_t {
    sockaddr_storage_t client_addr;  // both ipv4 and ipv6

#if defined _WIN32 || defined _WIN64
    netbuffer_t netio_read;
#endif
};

netsocket_event_t netsock_event;

return_t async_handler(accept_context_t* accept_context, netsocket_event_t* netsock_event) {
    return_t ret = errorcode_t::success;
#if defined _WIN32 || defined _WIN64
    uint32 flags = 0;
    netbuffer_t& wsabuf_read = netsock_event->netio_read;
    wsabuf_read.init();
    int addrlen = sizeof(sockaddr_storage_t);
    WSARecvFrom(accept_context->udp_server_sock, &wsabuf_read.wsabuf, 1, nullptr, &flags, (sockaddr*)&netsock_event->client_addr, &addrlen,
                &wsabuf_read.overlapped, nullptr);
#endif
    return ret;
}

return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    accept_context_t* accept_context = (accept_context_t*)user_context;
    return_t ret = errorcode_t::success;
    std::string address;

    if (mux_dgram == type) {
#if defined __linux__
        multiplexer_context_t* handle = (multiplexer_context_t*)data_array[0];
        int sock = (int)(long)data_array[1];
        char buffer[BUFSIZE];
        sockaddr_storage_t addr;
        socklen_t socklen = sizeof(sockaddr_storage_t);
        int ret_recv = recvfrom(sock, buffer, (int)sizeof(buffer), 0, (sockaddr*)&addr, &socklen);
        if (ret_recv > 0) {
            sockaddr_string(addr, address);
            _logger->writeln("[%d][%s][len %d] %.*s", sock, address.c_str(), (int)ret_recv, (int)ret_recv, buffer);
            sendto(sock, buffer, ret_recv, 0, (sockaddr*)&addr, socklen);
        }
#elif defined _WIN32 || defined _WIN64
        uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
        netsocket_event_t* netsock_event_ptr = (netsocket_event_t*)data_array[2];
        auto sock = accept_context->udp_server_sock;
        auto& addr = netsock_event_ptr->client_addr;

        uint32 flags = 0;
        netbuffer_t& wsabuf_read = netsock_event_ptr->netio_read;
        sockaddr_string(addr, address);

        _logger->writeln("[%d][%s][len %d] %.*s", sock, address.c_str(), (int)bytes_transfered, (int)bytes_transfered, wsabuf_read.wsabuf.buf);

        wsabuf_read.wsabuf.len = bytes_transfered;
        int addrlen = sizeof(sockaddr_storage_t);
        WSASendTo(sock, &wsabuf_read.wsabuf, 1, nullptr, flags, (sockaddr*)&addr, addrlen, nullptr, nullptr);

        async_handler(accept_context, &netsock_event);
#endif
    }
    return 0;
}

return_t producer_thread_routine(void* user_context) {
    accept_context_t* accept_context = (accept_context_t*)user_context;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    mplexer.event_loop_run(accept_context->mplex_handle, (handle_t)accept_context->udp_server_sock, consumer_routine, user_context);

    return 0;
}

return_t producer_signal_routine(void* param) {
    return_t ret = errorcode_t::success;
    accept_context_t* accept_context = (accept_context_t*)param;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    mplexer.event_loop_break_concurrent(accept_context->mplex_handle, 1);

    return ret;
}

return_t udp_server(void* param) {
    const OPTION& option = _cmdline->value();

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

    naive_udp_server_socket svr;
    multiplexer_context_t* handle_ipv4 = nullptr;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    signalwait_threads producer_threads;
    accept_context_t accept_context;
    socket_context_t* handle = nullptr;

    svr.open(&handle, AF_INET, option.port);  // IPv4 only
    auto sock = handle->fd;

    mplexer.open(&handle_ipv4, 128);
    mplexer.bind(handle_ipv4, (handle_t)handle->fd, &netsock_event);  // windows

    accept_context.mplex_handle = handle_ipv4;
    accept_context.udp_server_sock = sock;
    producer_threads.set(1, producer_thread_routine, producer_signal_routine, &accept_context);
    producer_threads.create();

#if defined _WIN32 || defined _WIN64
    // asynchronous read
    async_handler(&accept_context, &netsock_event);
#endif

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

    svr.close(handle);

    producer_threads.signal_and_wait_all();

    mplexer.close(handle_ipv4);

    return 0;
}

void run_server() {
    _test_case.begin("echo server (udp powered by multiplexer)");

    thread thread1(udp_server, nullptr);

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}
