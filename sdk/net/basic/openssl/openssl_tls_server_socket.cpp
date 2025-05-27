/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/nostd/exception.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/net/basic/openssl/openssl_tls_server_socket.hpp>

namespace hotplace {
namespace net {

openssl_tls_server_socket::openssl_tls_server_socket(openssl_tls* tls) : naive_tcp_server_socket(), _tls(tls) {
    if (nullptr == tls) {
        throw exception(errorcode_t::not_specified);
    }
    tls->addref();
}

openssl_tls_server_socket::~openssl_tls_server_socket() { _tls->release(); }

return_t openssl_tls_server_socket::tls_accept(socket_context_t** handle, socket_t cli_socket) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = _tls->tls_handshake(handle, cli_socket); /* new TLS_CONTEXT, to release see close member  */
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_tls_server_socket::tls_stop_accept() {
    return_t ret = errorcode_t::success;
    openssl_thread_end();  // ssl23_accept memory leak, call for each thread
    return ret;
}

return_t openssl_tls_server_socket::read(socket_context_t* handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = _tls->read(handle, mode, ptr_data, size_data, cbread);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_tls_server_socket::send(socket_context_t* handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == _tls) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        int mode = tls_io_flag_t::send_all;
        ret = _tls->send(handle, mode, ptr_data, size_data, cbsent);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool openssl_tls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
