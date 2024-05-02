/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto.hpp>
#include <sdk/net/tls/tls_server.hpp>

namespace hotplace {
using namespace crypto;
namespace net {

tls_server_socket::tls_server_socket(transport_layer_security* tls) : _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficient;
    }
    tls->addref();
    _shared.make_share(this);
}

tls_server_socket::~tls_server_socket() { _tls->release(); }

int tls_server_socket::addref() { return _shared.addref(); }

int tls_server_socket::release() { return _shared.delref(); }

return_t tls_server_socket::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);
        }
        tcp_server_socket::close(sock, tls_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_server_socket::tls_accept(socket_t clisock, tls_context_t** tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        ret = _tls->accept(tls_handle, clisock); /* new TLS_CONTEXT, to release see close member  */
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_server_socket::tls_stop_accept() {
    return_t ret = errorcode_t::success;

    openssl_thread_end();  // ssl23_accept memory leak, call for each thread
    return ret;
}

return_t tls_server_socket::read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->read(tls_handle, mode, ptr_data, size_data, cbread); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_server_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->send(tls_handle, tls_io_flag_t::send_all, ptr_data, size_data, cbsent); }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool tls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
