/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_composer::do_quic_client_handshake(unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

return_t tls_composer::do_quic_server_handshake(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

return_t tls_composer::do_quic_compose(quic_frame* frame, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

}  // namespace net
}  // namespace hotplace
