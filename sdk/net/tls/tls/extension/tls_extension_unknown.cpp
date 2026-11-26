/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_unknown.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_unknown.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_extension_unknown::tls_extension_unknown(tls_extension_type_t type, tls_handshake* handshake) : tls_extension(type, handshake) {}

tls_extension_unknown::~tls_extension_unknown() {}

return_t tls_extension_unknown::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    if (tls_extension_type_t::extended_master_secret == get_type()) {
        auto handshake = get_handshake();
        auto session = (handshake) ? handshake->get_session() : nullptr;
        bool valid_context = handshake && (((tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir)) ||
                                           ((tls_handshake_type_t::server_hello == handshake->get_type()) && (from_server == dir)));
        if (false == valid_context) {
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
            }
            return errorcode_t::bad_format;
        }
        if (0 != get_body_size()) {
            if (session) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
                session->reset_session_status();
            }
            return errorcode_t::bad_format;
        }
    }
    return errorcode_t::success;
}

return_t tls_extension_unknown::do_write_body(tls_direction_t dir, binary_t& bin) {
    if (tls_extension_type_t::extended_master_secret == get_type()) {
        auto handshake = get_handshake();
        bool valid_context = handshake && (((tls_handshake_type_t::client_hello == handshake->get_type()) && (from_client == dir)) ||
                                           ((tls_handshake_type_t::server_hello == handshake->get_type()) && (from_server == dir)));
        if (false == valid_context) {
            return errorcode_t::invalid_parameter;
        }
    }
    return errorcode_t::success;
}

}  // namespace net
}  // namespace hotplace
