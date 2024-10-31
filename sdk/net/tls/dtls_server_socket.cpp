/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/dtls_server_socket.hpp>

namespace hotplace {
namespace net {

dtls_server_socket::dtls_server_socket(transport_layer_security* tls) : udp_server_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
    _shared.make_share(this);
}

dtls_server_socket::~dtls_server_socket() { _tls->release(); }

return_t dtls_server_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);
        }
        // do not close socket
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::dtls_open(tls_context_t** tls_handle, socket_t sock) {
    return_t ret = errorcode_t::success;
    tls_context_t* context = nullptr;

    __try2 {
        if (nullptr == tls_handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 flags = 0;
#if defined _WIN32 || defined _WIN64
        // flags = tls_nbio;
#endif
        ret = _tls->dtls_open(&context, sock, flags);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        *tls_handle = context;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::dtls_handshake(tls_context_t* handle, sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    __try2 {
        ret = _tls->dtls_handshake(handle, addr, addrlen);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::recvfrom(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread,
                                      struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->recvfrom(tls_handle, mode, ptr_data, size_data, cbread, addr, addrlen); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::sendto(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent,
                                    const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;

    int mode = tls_io_flag_t::send_ssl_write;
    __try2 { ret = _tls->sendto(tls_handle, mode, ptr_data, size_data, cbsent, addr, addrlen); }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool dtls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
