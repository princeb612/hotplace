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

#include <sdk/io/system/socket.hpp>
#include <sdk/net/tls/dtls_client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

dtls_client_socket::dtls_client_socket(transport_layer_security* tls) : udp_client_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
}

dtls_client_socket::~dtls_client_socket() { _tls->release(); }

return_t dtls_client_socket::connectto(socket_t sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == tls_handle || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_context_t* handle = nullptr;
        ret = _tls->connectto(&handle, sock, address, port, timeout);
        if (errorcode_t::success == ret) {
            *tls_handle = handle;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_client_socket::connectto(socket_t sock, tls_context_t** tls_handle, const sockaddr* addr, socklen_t addrlen, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == tls_handle || nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_context_t* handle = nullptr;
        ret = _tls->connectto(&handle, sock, addr, addrlen, timeout);
        if (errorcode_t::success == ret) {
            *tls_handle = handle;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_client_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);  // closure notification
        }
        client_socket::close(sock, tls_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_client_socket::recvfrom(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr,
                                      socklen_t* addrlen) {
    return_t ret = errorcode_t::success;

    while (true) {
        ret = wait_socket(sock, get_wto(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
            int mode = tls_io_flag_t::read_ssl_read | tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv;
            ret = _tls->recvfrom(tls_handle, mode, ptr_data, size_data, cbread, addr, addrlen);
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

return_t dtls_client_socket::sendto(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent,
                                    const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    int mode = tls_io_flag_t::send_all;
    ret = _tls->sendto(tls_handle, mode, ptr_data, size_data, cbsent, addr, addrlen);
    return ret;
}

bool dtls_client_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
