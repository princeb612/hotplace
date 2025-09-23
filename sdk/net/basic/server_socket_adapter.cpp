/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/server_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>

namespace hotplace {
namespace net {

server_socket_adapter::server_socket_adapter() { _shared.make_share(this); }

server_socket_adapter::~server_socket_adapter() {}

uint32 server_socket_adapter::get_adapter_scheme(uint32 scheme, return_t& retcode) {
    // override
    retcode = errorcode_t::success;
    return scheme;
}

return_t server_socket_adapter::startup(uint32 scheme, const std::string& server_cert, const std::string& server_key, const std::string& cipher_suites,
                                        int verify_peer) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint32 flags = 0;
        uint32 scheme_masked = scheme & socket_scheme_mask;

        flags = get_adapter_scheme(scheme, ret);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        server_socket_builder builder;
        auto s = builder.set(flags).set_certificate(server_cert, server_key).set_ciphersuites(cipher_suites).set_verify(verify_peer).build();
        if (nullptr == s) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        critical_section_guard guard(_lock);
        _sockets.insert({scheme_masked, s});
    }
    __finally2 {}
    return ret;
}

return_t server_socket_adapter::shutdown(uint32 scheme) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint32 scheme_masked = scheme & socket_scheme_mask;

        critical_section_guard guard(_lock);
        auto iter = _sockets.find(scheme_masked);
        if (_sockets.end() != iter) {
            auto s = iter->second;
            s->release();
            _sockets.erase(iter);
        }
    }
    __finally2 {}
    return ret;
}

server_socket* server_socket_adapter::get_server_socket(uint32 scheme) {
    server_socket* svrsocket = nullptr;
    __try2 {
        uint32 scheme_masked = scheme & socket_scheme_mask;

        critical_section_guard guard(_lock);
        auto iter = _sockets.find(scheme_masked);
        if (_sockets.end() != iter) {
            svrsocket = iter->second;
        }
    }
    __finally2 {}
    return svrsocket;
}

return_t server_socket_adapter::enable_alpn(const char* prot) { return errorcode_t::not_implemented; }

void server_socket_adapter::addref() { _shared.addref(); }

void server_socket_adapter::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
