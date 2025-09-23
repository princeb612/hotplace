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

trial_server_socket_adapter::trial_server_socket_adapter() : server_socket_adapter() {}

trial_server_socket_adapter::~trial_server_socket_adapter() {}

uint32 trial_server_socket_adapter::get_adapter_scheme(uint32 scheme, return_t& retcode) {
    retcode = errorcode_t::success;

    uint32 scheme_masked = scheme & socket_scheme_mask;
    switch (scheme_masked) {
        case socket_scheme_tls:
        case socket_scheme_dtls:
        case socket_scheme_quic:
        case socket_scheme_quic2: {
            scheme |= socket_scheme_trial;
        } break;
        default: {
            retcode = errorcode_t::not_supported;
        } break;
    }

    return scheme;
}

return_t trial_server_socket_adapter::enable_alpn(const char* prot) {
    return_t ret = errorcode_t::success;
    auto tlsadvisor = tls_advisor::get_instance();
    ret = tlsadvisor->enable_alpn(prot);
    return ret;
}

}  // namespace net
}  // namespace hotplace
