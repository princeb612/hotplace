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
#include <sdk/net/tls/dtls_server_socket.hpp>

namespace hotplace {
using namespace crypto;
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

return_t dtls_server_socket::dtls_listen(socket_t sock, struct sockaddr* addr, socklen_t addrlen, tls_context_t** tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        ret = _tls->dtls_listen(tls_handle, sock, addr, addrlen);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::tls_accept(socket_t clisock, tls_context_t** tls_handle) {
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

return_t dtls_server_socket::tls_stop_accept() {
    return_t ret = errorcode_t::success;
    openssl_thread_end();  // ssl23_accept memory leak, call for each thread
    return ret;
}

return_t dtls_server_socket::read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->read(tls_handle, mode, ptr_data, size_data, cbread); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls_server_socket::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->send(tls_handle, tls_io_flag_t::send_all, ptr_data, size_data, cbsent); }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool dtls_server_socket::support_tls() { return true; }

}  // namespace net
}  // namespace hotplace
