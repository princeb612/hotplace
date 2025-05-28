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
#include <sdk/net/basic/trial/trial_server_socket_adapter.hpp>
#include <sdk/net/basic/trial/trial_tls_server_socket.hpp>
#include <sdk/net/tls/sdk.hpp>

namespace hotplace {
namespace net {

trial_server_socket_adapter::trial_server_socket_adapter() : server_socket_adapter(), _tls_server_socket(nullptr) {}

return_t trial_server_socket_adapter::startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list,
                                                  int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        load_certificate(server_cert.c_str(), server_key.c_str(), nullptr);
        __try_new_catch(_tls_server_socket, new trial_tls_server_socket, ret, __leave2);
    }
    __finally2 {}
    return ret;
}

return_t trial_server_socket_adapter::startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list,
                                                   int verify_peer) {
    return errorcode_t::not_supported;
}

return_t trial_server_socket_adapter::shutdown_tls() {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_tls_server_socket) {
            _tls_server_socket->release();
            _tls_server_socket = nullptr;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t trial_server_socket_adapter::shutdown_dtls() {
    return_t ret = errorcode_t::success;
    __try2 { ret = errorcode_t::not_supported; }
    __finally2 {
        // do nothing
    }
    return ret;
}

server_socket* trial_server_socket_adapter::get_tcp_server_socket() { return &_server_socket; }

server_socket* trial_server_socket_adapter::get_tls_server_socket() { return _tls_server_socket; }

server_socket* trial_server_socket_adapter::get_dtls_server_socket() { return nullptr; }

return_t trial_server_socket_adapter::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == prot) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == strcmp(prot, "h2")) {
            // TODO
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
