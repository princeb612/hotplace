/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/net/tls/tls_server.hpp>

namespace hotplace {
using namespace crypto;
namespace net {

transport_layer_security_server::transport_layer_security_server(transport_layer_security* tls) : _tls(tls) {
    if (nullptr == tls) {
        throw errorcode_t::insufficiency;
    }
    tls->addref();
    _shared.make_share(this);
}

transport_layer_security_server::~transport_layer_security_server() { _tls->release(); }

int transport_layer_security_server::addref() { return _shared.addref(); }

int transport_layer_security_server::release() { return _shared.delref(); }

return_t transport_layer_security_server::close(socket_t sock, tls_context_t* tls_handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr != tls_handle) {
            _tls->close(tls_handle);
        }
        server_socket::close(sock, tls_handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security_server::tls_accept(socket_t clisock, tls_context_t** tls_handle) {
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

return_t transport_layer_security_server::tls_stop_accept() {
    return_t ret = errorcode_t::success;

    openssl_thread_end();  // ssl23_accept memory leak, call for each thread
    return ret;
}

return_t transport_layer_security_server::read(socket_t sock, tls_context_t* tls_handle, int mode, char* ptr_data, size_t size_data, size_t* cbread) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->read(tls_handle, mode, ptr_data, size_data, cbread); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security_server::send(socket_t sock, tls_context_t* tls_handle, const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;

    __try2 { ret = _tls->send(tls_handle, tls_io_flag_t::send_all, ptr_data, size_data, cbsent); }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t transport_layer_security_server::query(int specid, arch_t* data_ptr) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data_ptr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        *data_ptr = 0;
        switch (specid) {
            case server_socket_query_t::query_support_tls:
                *data_ptr = 1;
                break;
            default:
                ret = errorcode_t::request;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
