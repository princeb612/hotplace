/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/system/socket.hpp>
#include <sdk/net/tls/tls_client_socket.hpp>

namespace hotplace {
using namespace io;
namespace net {

tls_client_socket::tls_client_socket(transport_layer_security* tls) : tcp_client_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
}

tls_client_socket::~tls_client_socket() { _tls->release(); }

return_t tls_client_socket::connect(socket_t* sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == sock || nullptr == tls_handle || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tls_context_t* handle = nullptr;
        ret = _tls->connect(&handle, SOCK_STREAM, address, port, timeout);
        if (errorcode_t::success == ret) {
            *sock = _tls->get_socket(handle);
            *tls_handle = handle;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_client_socket::connectto(socket_t sock, tls_context_t** tls_handle, const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == tls_handle || nullptr == address) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tls_context_t* handle = nullptr;
        ret = _tls->connect(&handle, sock, timeout);
        if (errorcode_t::success == ret) {
            *tls_handle = handle;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_client_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);
        }
        client_socket::close(sock, tls_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_client_socket::read(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    /*
     * case ... server sent 10 bytes, and client recv buffer size 8
     * recv 8 (SSL_read SSL_ERROR_WANT_READ)
     * recv 2 (SSL_read SUCCESS)
     * in case read 8 bytes and 2 bytes remains, return errorcode_t::more_data
     */
    while (true) {
        ret = wait_socket(sock, get_wto(), SOCK_WAIT_READABLE);
        if (errorcode_t::success == ret) {
            ret = _tls->read(tls_handle, tls_io_flag_t::read_ssl_read | tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv, ptr_data, size_data,
                             cbread);
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

return_t tls_client_socket::more(socket_t sock, tls_context_t* tls_handle, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    ret = _tls->read(tls_handle, tls_io_flag_t::read_ssl_read, ptr_data, size_data, cbread);
    return ret;
}

return_t tls_client_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    ret = _tls->send(tls_handle, tls_io_flag_t::send_all, ptr_data, size_data, cbsent);
    return ret;
}

bool tls_client_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
