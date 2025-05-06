/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *      DTLS not supported yet
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/exception.hpp>
#include <sdk/net/basic/openssl/dtls_client_socket.hpp>

namespace hotplace {
namespace net {

dtls_client_socket::dtls_client_socket(openssl_tls* tls) : client_socket(), _tls(tls), _handle(nullptr) {
    if (nullptr == tls) {
        throw exception(errorcode_t::not_specified);
    }
    tls->addref();
}

dtls_client_socket::~dtls_client_socket() { _tls->release(); }

return_t dtls_client_socket::open(sockaddr_storage_t* sa, const char* address, uint16 port) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (_handle) {
            ret = errorcode_t::already_assigned;
            __leave2;
        }
        if (nullptr == sa || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        socket_t sock = INVALID_SOCKET;
        create_socket(&sock, sa, SOCK_DGRAM, address, port);

        // TLS handshake
        socket_context_t* context = nullptr;
        ret = _tls->connectto(&context, sock, address, port, 3000);
        if (errorcode_t::success == ret) {
            context->flags |= closesocket_ondestroy;
            _handle = context;
        }
    }
    __finally2 {}

    return ret;
}

return_t dtls_client_socket::close() {
    return_t ret = errorcode_t::success;
    __try2 {
        _tls->close(_handle);
        _handle = nullptr;
    }
    __finally2 {}
    return ret;
}

return_t dtls_client_socket::recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    while (true) {
        auto fd = _handle->fd;
        ret = wait_socket(fd, get_wto(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
            int mode = tls_io_flag_t::read_ssl_read | tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv;
            ret = _tls->recvfrom(_handle, mode, ptr_data, size_data, cbread, addr, addrlen);
            if (errorcode_t::pending == ret) {
                continue;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    return ret;
}

return_t dtls_client_socket::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    int mode = tls_io_flag_t::send_all;
    ret = _tls->sendto(_handle, mode, ptr_data, size_data, cbsent, addr, addrlen);
    return ret;
}

bool dtls_client_socket::support_tls() { return true; }

int dtls_client_socket::socket_type() { return SOCK_DGRAM; }

socket_t dtls_client_socket::get_socket() {
    socket_t sock = INVALID_SOCKET;
    if (_handle) {
        sock = _handle->fd;
    }
    return sock;
}

}  // namespace net
}  // namespace hotplace
