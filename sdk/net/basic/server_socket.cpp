/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/server_socket.hpp>

namespace hotplace {
namespace net {

server_socket::server_socket() : basic_socket() {}

server_socket::~server_socket() {}

return_t server_socket::open(socket_t* sock, unsigned int family, uint16 port) { return errorcode_t::do_nothing; }

return_t server_socket::close(socket_t sock, tls_context_t* handle) { return close_socket(sock, true, 0); }

return_t server_socket::accept(socket_t sock, socket_t* clisock, struct sockaddr* addr, socklen_t* addrlen) { return errorcode_t::do_nothing; }

return_t server_socket::dtls_open(tls_context_t** handle, socket_t sock) { return errorcode_t::do_nothing; }

return_t server_socket::dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen) { return errorcode_t::do_nothing; }

return_t server_socket::tls_accept(socket_t clisock, tls_context_t** handle) { return errorcode_t::not_supported; }

return_t server_socket::tls_stop_accept() { return errorcode_t::do_nothing; }

return_t server_socket::read(socket_t sock, tls_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return errorcode_t::do_nothing;
}

return_t server_socket::recvfrom(socket_t sock, tls_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                 socklen_t* addrlen) {
    return errorcode_t::do_nothing;
}

return_t server_socket::send(socket_t sock, tls_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent) { return errorcode_t::do_nothing; }

return_t server_socket::sendto(socket_t sock, tls_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                               socklen_t addrlen) {
    return errorcode_t::do_nothing;
}

}  // namespace net
}  // namespace hotplace
