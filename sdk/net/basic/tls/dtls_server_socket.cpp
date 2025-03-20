/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/tls/dtls_server_socket.hpp>

namespace hotplace {
namespace net {

dtls_server_socket::dtls_server_socket(transport_layer_security* tls) : udp_server_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
}

dtls_server_socket::~dtls_server_socket() { _tls->release(); }

return_t dtls_server_socket::dtls_open(socket_context_t** handle, socket_t listen_sock) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        uint32 flags = 0;
#if defined _WIN32 || defined _WIN64
        // flags = tls_nbio;
#endif
        ret = _tls->dtls_open(handle, listen_sock, flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::dtls_handshake(socket_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = _tls->dtls_handshake(handle, addr, addrlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::recvfrom(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                      socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = _tls->recvfrom(handle, mode, ptr_data, size_data, cbread, addr, addrlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::sendto(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr,
                                    socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    int mode = tls_io_flag_t::send_ssl_write;
    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = _tls->sendto(handle, mode, ptr_data, size_data, cbsent, addr, addrlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool dtls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
