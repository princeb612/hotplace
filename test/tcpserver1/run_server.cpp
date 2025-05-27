/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @sa  See in the following order : tcpserver1, tcpserver2, tlsserver, httpserver1, httpauth, httpserver2
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

#define BUFSIZE 1024
#define FILENAME_RUN _T (".run")

typedef struct {
    multiplexer_context_t* mplex_handle;
    socket_t naive_tcp_server_socket;
} accept_context_t;

/* windows */
struct netsocket_event_t {
    socket_t cli_socket;
    sockaddr_storage_t client_addr;  // both ipv4 and ipv6

#if defined _WIN32 || defined _WIN64
    netbuffer_t netio_read;
#endif
};

return_t accept_thread_routine(void* user_context);
return_t producer_thread_routine(void* user_context);
return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context);

return_t client_connected_handler(socket_t sockcli, netsocket_event_t** out_netsocket_context) {
    return_t ret = errorcode_t::success;

    netsocket_event_t* netsocket_event = netsocket_event = new netsocket_event_t;
    sockaddr_storage_t sockaddr_client;
    int sockaddr_len = sizeof(sockaddr_client);

    netsocket_event->cli_socket = sockcli;
    getpeername(sockcli, (struct sockaddr*)&sockaddr_client, (socklen_t*)&sockaddr_len);
    memcpy(&(netsocket_event->client_addr), &sockaddr_client, sockaddr_len);

    *out_netsocket_context = netsocket_event;

    _logger->writeln("accept %d", (int)sockcli);

    _test_case.test(ret, __FUNCTION__, "accepted");

    return ret;
}

return_t client_disconnected_handler(netsocket_event_t* netsocket_event, void* user_context) {
    return_t ret = errorcode_t::success;
    accept_context_t* accept_context = (accept_context_t*)user_context;

    _logger->writeln("closed [%d]", (int)netsocket_event->cli_socket);

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif

    mplexer.unbind(accept_context->mplex_handle, (handle_t)netsocket_event->cli_socket, nullptr);

#if defined __linux__
    close(netsocket_event->cli_socket);
#elif defined _WIN32 || defined _WIN64
    closesocket(netsocket_event->cli_socket);
#endif
    delete netsocket_event;

    _test_case.test(ret, __FUNCTION__, "disconnected");

    return ret;
}

return_t async_handler(netsocket_event_t* netsocket_event) {
    return_t ret = errorcode_t::success;

#if defined _WIN32 || defined _WIN64
    DWORD flags = 0;
    DWORD bytes_received = 0;
    netbuffer_t& netbuffer = netsocket_event->netio_read;

    netbuffer.init();
    WSARecv(netsocket_event->cli_socket, &(netbuffer.wsabuf), 1, &bytes_received, &flags, &(netbuffer.overlapped), nullptr); /* asynchronus read */
#endif

    return ret;
}

return_t accept_thread_routine(void* user_context) {
    accept_context_t* context = (accept_context_t*)user_context;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    multiplexer_context_t* handle = context->mplex_handle;
    socket_t hServSock = (socket_t)context->naive_tcp_server_socket;

    _test_case.test(errorcode_t::success, __FUNCTION__, "accepting");

    while (true) {
        socket_t clisock = INVALID_SOCKET;
        sockaddr_storage_t addr;
        socklen_t addrLen = sizeof(addr);

        clisock = accept(hServSock, (struct sockaddr*)&addr, &addrLen);
        if (INVALID_SOCKET == clisock) {
            break;
        }

        netsocket_event_t* netsocket_event = nullptr;

        client_connected_handler(clisock, &netsocket_event);
        mplexer.bind(handle, (handle_t)clisock, netsocket_event);
#if defined _WIN32 || defined _WIN64
        async_handler(netsocket_event);
#endif
    }
    return 0;
}

return_t consumer_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
#if defined __linux__

    multiplexer_epoll mplexer;
    multiplexer_context_t* handle = (multiplexer_context_t*)data_array[0];

    if (mux_connect == type) {
        int socklisten = (int)(long)data_array[1];

        sockaddr_storage_t sockaddr;
        socklen_t sizeaddr = sizeof(sockaddr);

        int sockcli = accept(socklisten, (struct sockaddr*)&sockaddr, &sizeaddr);
        if (sockcli < 0) {
            *callback_control = STOP_CONTROL;
        } else {
            mplexer.bind(handle, sockcli, nullptr);

            char ipaddr[32] = {0};
            inet_ntop(sockaddr.ss_family, &((struct sockaddr_in*)&sockaddr)->sin_addr.s_addr, ipaddr, sizeof(ipaddr));

            _logger->writeln("accept [%d][%s]", sockcli, ipaddr);
        }
    }
    if (mux_read == type) {
        int sockcli = (int)(long)data_array[1];

        char buf[1024];
        int ret_recv = recv(sockcli, buf, 1024, 0);
        if (ret_recv <= 0) {
            _logger->writeln("connection closed [%d]", sockcli);
            mplexer.unbind(handle, sockcli, nullptr);
            close(sockcli);
        } else {
            _logger->writeln("[%d][len %d] %.*s", sockcli, ret_recv, ret_recv, buf);
            send(sockcli, buf, ret_recv, 0);
        }
    }
    if (mux_disconnect == type) {
        int sockcli = (int)(long)data_array[1];
        _logger->writeln("closed [%d]", sockcli);
        mplexer.unbind(handle, sockcli, nullptr);
        close(sockcli);
    }

#elif defined _WIN32 || defined _WIN64

    uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
    netsocket_event_t* netsocket_event = (netsocket_event_t*)data_array[2];

    __try2 {
        if (mux_read == type) {
            auto sockcli = netsocket_event->cli_socket;
            netbuffer_t& wsabuf_read = netsocket_event->netio_read;
            wsabuf_read.wsabuf.len = bytes_transfered;

            _logger->writeln("[%d][len %d] %.*s", sockcli, (int)bytes_transfered, (int)bytes_transfered, wsabuf_read.wsabuf.buf);

            /* echo */
            DWORD size_sent = 0;
            WSASend(sockcli, &(wsabuf_read.wsabuf), 1, &size_sent, 0, nullptr, nullptr);

            async_handler(netsocket_event);
        }
        if (mux_disconnect == type) {
            client_disconnected_handler(netsocket_event, user_context);
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }

#endif

    return 0;
}

return_t producer_thread_routine(void* user_context) {
    accept_context_t* accept_context = (accept_context_t*)user_context;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    mplexer.event_loop_run(accept_context->mplex_handle, (handle_t)accept_context->naive_tcp_server_socket, consumer_routine, user_context);

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

return_t echo_server(void* param) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    FILE* fp = fopen(FILENAME_RUN, "w");

    fclose(fp);

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    multiplexer_context_t* handle_ipv4 = nullptr;
    multiplexer_context_t* handle_ipv6 = nullptr;
    int i = 0;

    signalwait_threads acceptipv4_threads;
    signalwait_threads acceptipv6_threads;
    signalwait_threads networkipv4_threads;
    signalwait_threads networkipv6_threads;

    // int socketflags = 0;

    __try2 {
        ret = mplexer.open(&handle_ipv4, 1024);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = mplexer.open(&handle_ipv6, 1024);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        unsigned int family[2] = {AF_INET, AF_INET6};  // IPv4 and IPv6
        socket_t socket_list[2] = {INVALID_SOCKET, INVALID_SOCKET};

        create_listener(2, family, socket_list, IPPROTO_TCP, option.port);
        _logger->writeln("socket ipv4[%d], ipv6[%d] created", (int)socket_list[0], (int)socket_list[1]);

        accept_context_t accept_context_ipv4;
        accept_context_t accept_context_ipv6;
        accept_context_ipv4.mplex_handle = handle_ipv4;
        accept_context_ipv4.naive_tcp_server_socket = socket_list[0];
        accept_context_ipv6.mplex_handle = handle_ipv6;
        accept_context_ipv6.naive_tcp_server_socket = socket_list[1];

        // acceptxxx_threads signal handler ... just call CloseListener
        acceptipv4_threads.set(1, accept_thread_routine, nullptr, &accept_context_ipv4);
        acceptipv6_threads.set(1, accept_thread_routine, nullptr, &accept_context_ipv6);
        networkipv4_threads.set(64, producer_thread_routine, producer_signal_routine, &accept_context_ipv4);
        networkipv6_threads.set(64, producer_thread_routine, producer_signal_routine, &accept_context_ipv6);

        int producer_thread_count = 2;
#if defined __linux__

        /* epoll 은 listen socket 바인딩 */
        /* listen socket 이벤트를 수신하면 accept 호출, client socket 은 listen socket 바인딩 */

        mplexer.bind(handle_ipv4, socket_list[0], nullptr);
        mplexer.bind(handle_ipv6, socket_list[1], nullptr);

#elif defined _WIN32 || defined _WIN64

        /* iocp 은 listen socket 바인딩 불필요 */
        /* accept 호출후 연결된 client socket 을 iocp 바인딩 */

        acceptipv4_threads.create();
        acceptipv6_threads.create();

        SYSTEM_INFO SystemInfo;
        GetSystemInfo(&SystemInfo);

        producer_thread_count = SystemInfo.dwNumberOfProcessors;
#endif

        for (i = 0; i < producer_thread_count; i++) {
            networkipv4_threads.create();
            networkipv6_threads.create();
        }

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

        for (auto item : socket_list) {
            close_socket(item, true, 0);  // stop accepting
        }

        acceptipv4_threads.signal_and_wait_all();
        acceptipv6_threads.signal_and_wait_all();
        networkipv4_threads.signal_and_wait_all();
        networkipv6_threads.signal_and_wait_all();

        mplexer.close(handle_ipv4);
        mplexer.close(handle_ipv6);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

void run_server() {
    _test_case.begin("echo server (tcp powered by multiplexer)");

    thread thread1(echo_server, nullptr);

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}
