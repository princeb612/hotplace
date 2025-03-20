/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/tls/tls_client_socket.hpp>

namespace hotplace {
namespace net {

tls_client_socket::tls_client_socket(transport_layer_security* tls) : client_socket(), _tls(tls), _handle(nullptr) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
}

tls_client_socket::~tls_client_socket() { _tls->release(); }

return_t tls_client_socket::connect(const char* address, uint16 port, uint32 timeout) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_handle) {
            ret = errorcode_t::already_assigned;
            __leave2;
        }

        auto type = socket_type();
        socket_context_t* context = nullptr;
        ret = _tls->connect(&context, type, address, port, timeout);
        if (errorcode_t::success == ret) {
            context->flags |= closesocket_ondestroy;
            _handle = context;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_client_socket::close() {
    return_t ret = errorcode_t::success;
    __try2 {
        _tls->close(_handle);
        _handle = nullptr;
    }
    __finally2 {}
    return ret;
}

return_t tls_client_socket::read(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        /*
         * case ... server sent 10 bytes, and client recv buffer size 8
         * recv 8 (SSL_read SSL_ERROR_WANT_READ)
         * recv 2 (SSL_read SUCCESS)
         * in case read 8 bytes and 2 bytes remains, return errorcode_t::more_data
         */
        auto sock = _handle->fd;
        while (true) {
            return_t test = wait_socket(sock, get_wto(), SOCK_WAIT_READABLE);
            if (errorcode_t::success == test) {
                int mode = tls_io_flag_t::read_ssl_read | tls_io_flag_t::read_bio_write | tls_io_flag_t::read_socket_recv;
                test = _tls->read(_handle, mode, ptr_data, size_data, cbread);
                if (errorcode_t::pending == test) {
                    continue;
                } else {
                    ret = test;
                    break;
                }
            } else {
                break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_client_socket::more(char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        int mode = tls_io_flag_t::read_ssl_read;
        ret = _tls->read(_handle, mode, ptr_data, size_data, cbread);
    }
    __finally2 {}
    return ret;
}

return_t tls_client_socket::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        int mode = tls_io_flag_t::send_all;
        ret = _tls->send(_handle, mode, ptr_data, size_data, cbsent);
    }
    __finally2 {}
    return ret;
}

bool tls_client_socket::support_tls() { return true; }

int tls_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
