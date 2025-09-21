/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/openssl/openssl_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_server_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket_builder.hpp>
#include <hotplace/sdk/net/basic/trial/trial_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_quic_server_socket.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <hotplace/sdk/net/tls/sdk.hpp>

namespace hotplace {
namespace net {

server_socket_builder::server_socket_builder() : _verify(0) {}

server_socket_builder& server_socket_builder::set(uint32 scheme) {
    _scheme = scheme;
    return *this;
}

server_socket_builder& server_socket_builder::set_certificate(const std::string& server_cert, const std::string& server_key) {
    _server_cert = server_cert;
    _server_key = server_key;
    return *this;
}
server_socket_builder& server_socket_builder::set_ciphersuites(const std::string& cipher_suites) {
    _cipher_suites = cipher_suites;
    return *this;
}
server_socket_builder& server_socket_builder::set_verify(int verify_peer) {
    _verify = verify_peer;
    return *this;
}

server_socket* server_socket_builder::build() {
    server_socket* svrsocket = nullptr;
    __try2 {
        auto socket_scheme = socket_scheme_mask & get_scheme();
        auto powered_by = socket_scheme_mask_powered_by & get_scheme();
        auto secure = socket_scheme_mask_secure & get_scheme();
        switch (socket_scheme) {
            case socket_scheme_tcp: {
                __try_new_catch_only(svrsocket, new naive_tcp_server_socket);
            } break;
            case socket_scheme_udp: {
                __try_new_catch_only(svrsocket, new naive_udp_server_socket);
            } break;
            case socket_scheme_tls: {
                switch (powered_by) {
                    case socket_scheme_openssl: {
                        openssl_tls_context ctx(tlscontext_flag_tls, _server_cert.c_str(), _server_key.c_str());
                        __try_new_catch_only(svrsocket, new openssl_tls_server_socket(new openssl_tls(&ctx)));
                        ctx.set_cipher_list(_cipher_suites.c_str());
                        ctx.set_verify(_verify);
                    } break;
                    case socket_scheme_trial: {
                        __try_new_catch_only(svrsocket, new trial_tls_server_socket);
                    } break;
                }
            } break;
            case socket_scheme_dtls: {
                switch (powered_by) {
                    case socket_scheme_openssl: {
                        openssl_tls_context ctx(tlscontext_flag_dtls, _server_cert.c_str(), _server_key.c_str());
                        __try_new_catch_only(svrsocket, new openssl_dtls_server_socket(new openssl_tls(&ctx)));
                        ctx.set_cipher_list(_cipher_suites.c_str());
                        ctx.set_verify(_verify);
                    } break;
                    case socket_scheme_trial: {
                        __try_new_catch_only(svrsocket, new trial_dtls_server_socket);
                    } break;
                }
            } break;
            case socket_scheme_quic:
            case socket_scheme_quic2: {
                switch (powered_by) {
                    case socket_scheme_openssl: {
                        // not supported
                    } break;
                    case socket_scheme_trial: {
                        __try_new_catch_only(svrsocket, new trial_quic_server_socket);
                    } break;
                }
            } break;
        }

        if (svrsocket) {
            if (secure) {
                switch (powered_by) {
                    case socket_scheme_openssl: {
                    } break;
                    case socket_scheme_trial: {
                        load_certificate(_server_cert.c_str(), _server_key.c_str(), nullptr);
                        auto tlsadvisor = tls_advisor::get_instance();
                        tlsadvisor->set_ciphersuites(_cipher_suites.c_str());
                        // verify_peer not supported
                    } break;
                }
            }
        }
    }
    __finally2 {}
    return svrsocket;
}

uint32 server_socket_builder::get_scheme() { return _scheme; }

}  // namespace net
}  // namespace hotplace
