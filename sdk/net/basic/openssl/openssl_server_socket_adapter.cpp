/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/naive/naive_tcp_server_socket.hpp>
#include <sdk/net/basic/openssl/openssl_dtls_server_socket.hpp>
#include <sdk/net/basic/openssl/openssl_server_socket_adapter.hpp>
#include <sdk/net/basic/openssl/openssl_tls.hpp>
#include <sdk/net/basic/openssl/openssl_tls_context.hpp>
#include <sdk/net/basic/openssl/openssl_tls_server_socket.hpp>

namespace hotplace {
namespace net {

openssl_server_socket_adapter::openssl_server_socket_adapter()
    : server_socket_adapter(),
      _tlscert(nullptr),
      _tls(nullptr),
      _tls_server_socket(nullptr),
      _dtlscert(nullptr),
      _dtls(nullptr),
      _dtls_server_socket(nullptr) {}

return_t openssl_server_socket_adapter::startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list,
                                                    int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(_tlscert, new openssl_tls_context(tlscontext_flag_tls, server_cert.c_str(), server_key.c_str()), ret, __leave2);
        __try_new_catch(_tls, new openssl_tls(_tlscert->get_ctx()), ret, __leave2);
        __try_new_catch(_tls_server_socket, new openssl_tls_server_socket(_tls), ret, __leave2);

        _tlscert->set_cipher_list(cipher_list.c_str());
    }
    __finally2 {}
    return ret;
}

return_t openssl_server_socket_adapter::startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list,
                                                     int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        __try_new_catch(_dtlscert, new openssl_tls_context(tlscontext_flag_dtls, server_cert.c_str(), server_key.c_str()), ret, __leave2);
        __try_new_catch(_dtls, new openssl_tls(_dtlscert->get_ctx()), ret, __leave2);
        __try_new_catch(_dtls_server_socket, new openssl_dtls_server_socket(_dtls), ret, __leave2);
    }
    __finally2 {}
    return ret;
}

return_t openssl_server_socket_adapter::shutdown_tls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_tls_server_socket) {
            _tls_server_socket->release();
            _tls_server_socket = nullptr;
        }
        if (_tls) {
            _tls->release();
            _tls = nullptr;
        }
        if (_tlscert) {
            delete _tlscert;
            _tlscert = nullptr;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_server_socket_adapter::shutdown_dtls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_dtls_server_socket) {
            _dtls_server_socket->release();
            _dtls_server_socket = nullptr;
        }
        if (_dtls) {
            _dtls->release();
            _dtls = nullptr;
        }
        if (_dtlscert) {
            delete _dtlscert;
            _dtlscert = nullptr;
        }
    }
    __finally2 {}
    return ret;
}

server_socket* openssl_server_socket_adapter::get_tcp_server_socket() { return &_server_socket; }

server_socket* openssl_server_socket_adapter::get_tls_server_socket() { return _tls_server_socket; }

server_socket* openssl_server_socket_adapter::get_dtls_server_socket() { return _dtls_server_socket; }

openssl_tls_context* openssl_server_socket_adapter::get_tls_context() { return _tlscert; }

openssl_tls_context* openssl_server_socket_adapter::get_dtls_context() { return _dtlscert; }

return_t openssl_server_socket_adapter::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == prot) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == strcmp(prot, "h2")) {
            get_tls_context()->enable_alpn_h2(true);
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
