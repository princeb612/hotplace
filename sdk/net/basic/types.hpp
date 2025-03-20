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
class tlscert;

}  // namespace net
}  // namespace hotplace

#endif
