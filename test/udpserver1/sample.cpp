/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author  Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc    UDP server using multiplexer
 * @sa      See in the following order : udpserver, udpserver2, dtlsserver
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
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;
    uint16 port;

    _OPTION() : verbose(0), log(0), time(0), port(9000) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

#define BUFSIZE (1 << 16)
#define FILENAME_RUN _T (".run")

struct accept_context_t {
    multiplexer_context_t* mplex_handle;
    socket_t udp_server_sock;
};

#if defined _WIN32 || defined _WIN64
struct wsa_buffer_t {
    OVERLAPPED overlapped;
    WSABUF wsabuf;
    char buffer[BUFSIZE];

    wsa_buffer_t() { init(); }
    void init() {
        memset(&overlapped, 0, sizeof(overlapped));
        wsabuf.len = sizeof(buffer);
        wsabuf.buf = buffer;
    }
};
#endif

/* windows */
struct netsocket_event_t {
    sockaddr_storage_t client_addr;  // both ipv4 and ipv6

#if defined _WIN32 || defined _WIN64
    wsa_buffer_t netio_read;
#endif
};

netsocket_event_t netsock_event;

return_t async_handler(accept_context_t* accept_context, netsocket_event_t* netsock_event) {
    return_t ret = errorcode_t::success;
#if defined _WIN32 || defined _WIN64
    uint32 flags = 0;
    wsa_buffer_t& wsabuf_read = netsock_event->netio_read;
    wsabuf_read.init();
    int addrlen = sizeof(sockaddr_storage_t);
    WSARecvFrom(accept_context->udp_server_sock, &wsabuf_read.wsabuf, 1, nullptr, &flags, (sockaddr*)&netsock_event->client_addr, &addrlen,
                &wsabuf_read.overlapped, nullptr);
#endif
    return ret;
}

return_t consume_routine(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control, void* user_context) {
    accept_context_t* accept_context = (accept_context_t*)user_context;
    return_t ret = errorcode_t::success;

    if (mux_dgram == type) {
#if defined __linux__
        multiplexer_context_t* handle = (multiplexer_context_t*)data_array[0];
        int svr_cli = (int)(long)data_array[1];
        char buffer[BUFSIZE];
        sockaddr_storage_t sockaddr_storage;
        socklen_t socklen = sizeof(sockaddr_storage_t);
        int ret_recv = recvfrom(svr_cli, buffer, (int)sizeof(buffer), 0, (sockaddr*)&sockaddr_storage, &socklen);
        if (ret_recv > 0) {
            _logger->writeln("[%d] %.*s", (int)ret_recv, (int)ret_recv, buffer);
            sendto(svr_cli, buffer, ret_recv, 0, (sockaddr*)&sockaddr_storage, socklen);
        }
#elif defined _WIN32 || defined _WIN64
        uint32 bytes_transfered = (uint32)(arch_t)data_array[1];
        netsocket_event_t* netsock_event_ptr = (netsocket_event_t*)data_array[2];

        uint32 flags = 0;
        wsa_buffer_t& wsabuf_read = netsock_event_ptr->netio_read;

        _logger->writeln("[%d] %.*s", (int)bytes_transfered, (int)bytes_transfered, wsabuf_read.wsabuf.buf);

        wsabuf_read.wsabuf.len = bytes_transfered;
        int addrlen = sizeof(sockaddr_storage_t);
        WSASendTo(accept_context->udp_server_sock, &wsabuf_read.wsabuf, 1, nullptr, flags, (sockaddr*)&netsock_event_ptr->client_addr, addrlen, nullptr,
                  nullptr);

        async_handler(accept_context, &netsock_event);
#endif
    }
    return 0;
}

return_t network_thread_routine(void* user_context) {
    accept_context_t* accept_context = (accept_context_t*)user_context;

#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    mplexer.event_loop_run(accept_context->mplex_handle, (handle_t)accept_context->udp_server_sock, consume_routine, user_context);

    return 0;
}

return_t network_signal_routine(void* param) {
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

    udp_server_socket svr;
    multiplexer_context_t* handle_ipv4 = nullptr;
#if defined __linux__
    multiplexer_epoll mplexer;
#elif defined _WIN32 || defined _WIN64
    multiplexer_iocp mplexer;
#endif
    signalwait_threads network_threads;
    accept_context_t accept_context;
    socket_t sock = INVALID_SOCKET;

    svr.open(&sock, AF_INET, option.port);  // IPv4 only

    mplexer.open(&handle_ipv4, 128);
    mplexer.bind(handle_ipv4, (handle_t)sock, &netsock_event);  // windows

    accept_context.mplex_handle = handle_ipv4;
    accept_context.udp_server_sock = sock;
    network_threads.set(1, network_thread_routine, network_signal_routine, &accept_context);
    network_threads.create();

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

    svr.close(sock, nullptr);

    network_threads.signal_and_wait_all();

    mplexer.close(handle_ipv4);

    return 0;
}

void run_server() {
    _test_case.begin("echo server (udp powered by multiplexer)");

    thread thread1(udp_server, nullptr);

    __try2 { thread1.start(); }
    __finally2 { thread1.wait(-1); }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional()
              << t_cmdarg_t<OPTION>("-p", "port (9000)", [](OPTION& o, char* param) -> void { o.port = atoi(param); }).optional().preced();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

#if defined _WIN32 || defined _WIN64
    winsock_startup();
#endif
    openssl_startup();

    run_server();

    openssl_cleanup();

#if defined _WIN32 || defined _WIN64
    winsock_cleanup();
#endif

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
