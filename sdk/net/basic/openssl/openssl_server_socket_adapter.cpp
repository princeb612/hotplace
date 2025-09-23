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
#include <hotplace/sdk/net/basic/openssl/openssl_dtls_server_socket.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_server_socket_adapter.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_context.hpp>
#include <hotplace/sdk/net/basic/openssl/openssl_tls_server_socket.hpp>
#include <hotplace/sdk/net/basic/server_socket_builder.hpp>

namespace hotplace {
namespace net {

openssl_server_socket_adapter::openssl_server_socket_adapter() : server_socket_adapter() {}

openssl_server_socket_adapter::~openssl_server_socket_adapter() {}

uint32 openssl_server_socket_adapter::get_adapter_scheme(uint32 scheme, return_t& retcode) {
    retcode = errorcode_t::success;

    uint32 scheme_masked = scheme & socket_scheme_mask;
    switch (scheme_masked) {
        case socket_scheme_tls:
        case socket_scheme_dtls: {
            scheme |= socket_scheme_openssl;
        } break;
        case socket_scheme_quic:
        case socket_scheme_quic2:
        default: {
            retcode = errorcode_t::not_supported;
        } break;
    }

    return scheme;
}

return_t openssl_server_socket_adapter::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == prot) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == strcmp(prot, "h2")) {
            auto s = get_server_socket(socket_scheme_tls);
            if (s) {
                auto svrsocket = (openssl_tls_server_socket*)s;
                openssl_tls_context context(svrsocket->get_openssl_tls());
                context.enable_alpn_h2(true);
            }
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
