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

#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum tls_flag_t {
    closesocket_ondestroy = (1 << 0),
    tls_nbio = (1 << 1),
    closesocket_if_tcp = (1 << 2),
};

struct socket_context_t {
    socket_t fd;   // socket
    uint32 flags;  // see tls_flag_t
    SSL* ssl;      // TLS

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

    netsocket_t() : event_handle(nullptr) {}
    socket_t get_event_socket() { return event_handle->fd; }
    operator handle_t() { return (handle_t)get_event_socket(); }
};

class client_socket;
class ipaddr_acl;
class server_socket;
class tcp_client_socket;
class tcp_server_socket;
class udp_client_socket;
class udp_server_socket;

class dtls_client_socket;
class dtls_server_socket;
class tls_client_socket;
class tls_server_socket;
class transport_layer_security;
class tlscontext;

}  // namespace net
}  // namespace hotplace

#endif
