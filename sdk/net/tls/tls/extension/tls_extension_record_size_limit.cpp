/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_extension_record_size_limit.cpp
 * @author OpenAI
 * @desc   RFC 8449 Record Size Limit Extension
 */

#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_record_size_limit.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_extension_record_size_limit::tls_extension_record_size_limit(tls_handshake* handshake)
    : tls_extension(tls_extension_type_t::record_size_limit, handshake), _record_size_limit(1 << 14) {}

tls_extension_record_size_limit::~tls_extension_record_size_limit() {}

uint16 tls_extension_record_size_limit::get_record_size_limit() const { return _record_size_limit; }

void tls_extension_record_size_limit::set_record_size_limit(uint16 value) { _record_size_limit = value; }

static return_t validate_record_size_limit_context(tls_handshake* handshake, tls_direction_t dir, bool reading) {
    auto session = handshake->get_session();
    auto type = handshake->get_type();
    auto& protection = session->get_tls_protection();

    switch (type) {
        case tls_handshake_type_t::client_hello:
        case tls_handshake_type_t::server_hello:
            break;
        case tls_handshake_type_t::encrypted_extensions:
            if (false == protection.is_kindof_tls13()) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                return errorcode_t::handshake_failure;
            }
            break;
        default:
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
            return errorcode_t::handshake_failure;
    }

    // A server response is valid only if the client advertised its receive limit.
    if (from_server == dir) {
        auto offered = session->get_session_info(from_client).get_keyvalue().get(session_record_size_limit);
        if (0 == offered) {
            if (reading) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unsupported_extension);
                return errorcode_t::handshake_failure;
            }
            return errorcode_t::invalid_parameter;
        }
    }
    return errorcode_t::success;
}

return_t tls_extension_record_size_limit::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = validate_record_size_limit_context(get_handshake(), dir, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if ((nullptr == stream) || (endpos_extension() - pos != sizeof(uint16))) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        payload pl;
        pl << new payload_member(uint16(0), true, "record size limit");
        ret = pl.read(stream, endpos_extension(), pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        _record_size_limit = pl.t_value_of<uint16>("record size limit");
        if (_record_size_limit < 64) {
            auto session = get_handshake()->get_session();
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
            ret = errorcode_t::handshake_failure;
            __leave2;
        }

        get_handshake()->get_session()->get_session_info(dir).get_keyvalue().set(session_record_size_limit, _record_size_limit);
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_record_size_limit::do_write_body(tls_direction_t dir, binary_t& bin) {
    auto session = get_handshake()->get_session();
    auto context_ret = validate_record_size_limit_context(get_handshake(), dir, false);
    if (errorcode_t::success != context_ret) {
        return context_ret;
    }
    auto& protection = session->get_tls_protection();
    size_t max_record_size = protection.is_kindof_tls13() ? ((1 << 14) + 1) : (1 << 14);
    if ((_record_size_limit < 64) || (_record_size_limit > max_record_size)) {
        return errorcode_t::invalid_parameter;
    }

    binary_append(bin, _record_size_limit, hton16);
    session->get_session_info(dir).get_keyvalue().set(session_record_size_limit, _record_size_limit);
    return errorcode_t::success;
}

}  // namespace net
}  // namespace hotplace
