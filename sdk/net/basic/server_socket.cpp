/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/server_socket.hpp>

namespace hotplace {
namespace net {

server_socket::server_socket() {}

server_socket::~server_socket() {}

return_t server_socket::open(socket_context_t** handle, unsigned int family, uint16 port) { return errorcode_t::do_nothing; }

return_t server_socket::close(socket_context_t* handle) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        delete handle;
    }
    __finally2 {}
    return ret;
}

return_t server_socket::accept(socket_t* client_socket, socket_t listen_socket, struct sockaddr* addr, socklen_t* addrlen) { return errorcode_t::do_nothing; }

return_t server_socket::dtls_open(socket_context_t** handle, socket_t listen_socket) { return errorcode_t::do_nothing; }

return_t server_socket::dtls_handshake(socket_context_t* handle, sockaddr* addr, socklen_t addrlen) { return errorcode_t::do_nothing; }

return_t server_socket::dtls_handshake(netsession_t* sess) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == sess) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto event_handle = sess->netsock.event_handle;
        auto& addr = sess->netsock.cli_addr;
        ret = dtls_handshake(event_handle, (sockaddr*)&addr, sizeof(addr));
    }
    __finally2 {}
    return ret;
}

return_t server_socket::tls_accept(socket_context_t** handle, socket_t listen_socket) { return errorcode_t::do_nothing; }

return_t server_socket::tls_stop_accept() { return errorcode_t::do_nothing; }

return_t server_socket::read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) { return errorcode_t::do_nothing; }

return_t server_socket::recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                 socklen_t* addrlen) {
    return errorcode_t::do_nothing;
}

return_t server_socket::send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent) { return errorcode_t::do_nothing; }

return_t server_socket::sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                               socklen_t addrlen) {
    return errorcode_t::do_nothing;
}

}  // namespace net
}  // namespace hotplace
