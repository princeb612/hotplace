/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/naive/naive_tcp_server_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket_builder.hpp>
#include <hotplace/sdk/net/basic/trial/trial_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_quic_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <hotplace/sdk/net/tls/sdk.hpp>

namespace hotplace {
namespace net {

trial_server_socket_adapter::trial_server_socket_adapter() : server_socket_adapter(), _tls_server_socket(nullptr) {}

trial_server_socket_adapter::~trial_server_socket_adapter() {}

return_t trial_server_socket_adapter::startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites,
                                                  int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        server_socket_builder builder;
        auto s = builder.set(socket_scheme_tls | socket_scheme_trial)
                     .set_certificate(server_cert, server_key)
                     .set_ciphersuites(cipher_suites)
                     .set_verify(verify_peer)
                     .build();
        if (nullptr == s) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        _tls_server_socket = (trial_tls_server_socket*)s;
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites,
                                                   int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        server_socket_builder builder;
        auto s = builder.set(socket_scheme_dtls | socket_scheme_trial)
                     .set_certificate(server_cert, server_key)
                     .set_ciphersuites(cipher_suites)
                     .set_verify(verify_peer)
                     .build();
        if (nullptr == s) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        _dtls_server_socket = (trial_dtls_server_socket*)s;
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::startup_quic(const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites,
                                                   int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        server_socket_builder builder;
        auto s = builder.set(socket_scheme_quic | socket_scheme_trial)
                     .set_certificate(server_cert, server_key)
                     .set_ciphersuites(cipher_suites)
                     .set_verify(verify_peer)
                     .build();
        if (nullptr == s) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        _quic_server_socket = (trial_quic_server_socket*)s;
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::shutdown_tls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_tls_server_socket) {
            _tls_server_socket->release();
            _tls_server_socket = nullptr;
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::shutdown_dtls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_dtls_server_socket) {
            _dtls_server_socket->release();
            _dtls_server_socket = nullptr;
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::shutdown_quic() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_quic_server_socket) {
            _quic_server_socket->release();
            _quic_server_socket = nullptr;
        }
    }
    __finally2 {}
    return ret;
}

server_socket* trial_server_socket_adapter::get_tcp_server_socket() { return &_server_socket; }

server_socket* trial_server_socket_adapter::get_tls_server_socket() { return _tls_server_socket; }

server_socket* trial_server_socket_adapter::get_dtls_server_socket() { return _dtls_server_socket; }

server_socket* trial_server_socket_adapter::get_quic_server_socket() { return _quic_server_socket; }

return_t trial_server_socket_adapter::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    auto tlsadvisor = tls_advisor::get_instance();
    ret = tlsadvisor->enable_alpn(prot);
    return ret;
}

}  // namespace net
}  // namespace hotplace
