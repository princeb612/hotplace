/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_NET_BASIC_TYPES__
#define __HOTPLACE_SDK_NET_BASIC_TYPES__

#include <hotplace/sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum socket_context_flag_t {
    closesocket_ondestroy = (1 << 0),
    tls_nbio = (1 << 1),
    closesocket_if_tcp = (1 << 2),
    tls_using_openssl = (1 << 3),
};

enum tls_io_flag_t {
    read_ssl_read = (1 << 0),                                        // 0000 0001
    read_bio_write = (1 << 1),                                       // 0000 0010
    read_socket_recv = (1 << 2),                                     // 0000 0100
    send_ssl_write = (1 << 3),                                       // 0000 1000
    send_bio_read = (1 << 4),                                        // 0001 0000
    send_socket_send = (1 << 5),                                     // 0010 0000
    read_iocp = (read_bio_write),                                    // 0000 0010
    read_epoll = (read_bio_write | read_socket_recv),                // 0000 0110
    send_all = (send_ssl_write | send_bio_read | send_socket_send),  // 0011 1000
    peek_msg = (1 << 6),                                             // 0100 0000
};

class tls_session;
struct socket_context_t {
    socket_t fd;   // socket
    uint32 flags;  // see socket_context_flag_t
    union {
        SSL* ssl;  // TLS (openssl-specific)
        tls_session* session;
    } handle;

    socket_context_t();
    socket_context_t(socket_t s, uint32 f = closesocket_ondestroy);
    ~socket_context_t();
};

#define DEFAULT_NET_BUFFER_SIZE 1500

struct netbuffer_t {
#if defined __linux__
    char* buffer;
    size_t buflen;
#elif defined _WIN32 || defined _WIN64
    /* windows overlapped */
    // assign per socket
    OVERLAPPED overlapped;
    WSABUF wsabuf;
#endif

    std::vector<char> bin;
    size_t bufsize;

    netbuffer_t() { set_bufsize(DEFAULT_NET_BUFFER_SIZE); }
    void init() {
#if defined __linux__
        buffer = &bin[0];
        buflen = bin.size();
#elif defined _WIN32 || defined _WIN64
        memset(&overlapped, 0, sizeof(OVERLAPPED));
        wsabuf.len = bin.size();
        wsabuf.buf = &bin[0];
#endif
    }
    void set_bufsize(uint16 size) {
        if (size) {
            bufsize = size;
            bin.resize(bufsize);
            init();
        }
    }
};

struct netsocket_t {
    socket_context_t* event_handle;
    sockaddr_storage_t cli_addr;  // both ipv4 and ipv6

    netsocket_t() : event_handle(nullptr) { memset(&cli_addr, 0, sizeof(cli_addr)); }
    socket_t get_event_socket() { return event_handle->fd; }
    operator handle_t() { return (handle_t)get_event_socket(); }
};

class server_socket;
struct netsession_t {
    netbuffer_t buf;      // socket buffer (OVERLAPPED in windows)
    netsocket_t netsock;  // contains socket_context_t, sockaddr_storage_t

    void* mplexer_handle;
    server_socket* svr_socket;
    int priority;

    netsession_t() : mplexer_handle(nullptr), svr_socket(nullptr), priority(0) {}
    netsocket_t* socket_info() { return &netsock; }
    netbuffer_t& get_buffer() { return buf; }
};

class client_socket;
class ipaddr_acl;

class naive_tcp_client_socket;
class naive_tcp_server_socket;
class naive_udp_client_socket;
class naive_udp_server_socket;

class openssl_dtls_client_socket;
class openssl_dtls_server_socket;
class openssl_tls_client_socket;
class openssl_tls_server_socket;
class openssl_tls;
class openssl_tls_context;

class trial_tcp_client_socket;
class trial_udp_client_socket;
class trial_tls_client_socket;
class trial_dtls_client_socket;
class trial_quic_client_socket;
class trial_tls_server_socket;
class trial_dtls_server_socket;
class trial_quic_server_socket;

class server_socket_adapter;
class openssl_server_socket_adapter;
class trial_server_socket_adapter;

}  // namespace net
}  // namespace hotplace

#endif
