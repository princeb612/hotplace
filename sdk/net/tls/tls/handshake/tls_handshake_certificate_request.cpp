/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_certificate_request.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate_request.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_certificate_request::tls_handshake_certificate_request(tls_session* session) : tls_handshake(tls_handshake_type_t::certificate_request, session) {}

tls_handshake_certificate_request::~tls_handshake_certificate_request() {}

const binary_t& tls_handshake_certificate_request::get_request_context() const { return _request_context; }

void tls_handshake_certificate_request::set_request_context(const binary_t& context) { _request_context = context; }

return_t tls_handshake_certificate_request::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    return protection.update_transcript_hash(session, stream + offsetof_header(), get_size());
}

return_t tls_handshake_certificate_request::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream || pos > size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto fail_decode = [&]() -> void {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            ret = errorcode_t::bad_format;
        };

        size_t body_end = offsetof_body() + get_body_size();
        if (body_end > size || pos > body_end || body_end - pos < 3) {
            fail_decode();
            __leave2;
        }

        uint8 context_len = stream[pos++];
        if (context_len > body_end - pos || body_end - pos - context_len < 2) {
            fail_decode();
            __leave2;
        }
        _request_context.assign(stream + pos, stream + pos + context_len);
        pos += context_len;

        uint16 extensions_len = t_binary_to_integer<uint16>(stream + pos, sizeof(uint16));
        pos += sizeof(uint16);
        if (extensions_len != body_end - pos) {
            fail_decode();
            __leave2;
        }

        ret = get_extensions().read(this, dir, stream, body_end, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (pos != body_end) {
            fail_decode();
            __leave2;
        }

        if (nullptr == get_extensions().get(tls_extension_type_t::signature_algorithms)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
            ret = errorcode_t::bad_format;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_certificate_request::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (_request_context.size() > 255 || nullptr == get_extensions().get(tls_extension_type_t::signature_algorithms)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t extensions;
        ret = get_extensions().write(dir, extensions);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (extensions.size() > 0xffff) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bin.push_back((byte_t)_request_context.size());
        binary_append(bin, _request_context);
        binary_append(bin, (uint16)extensions.size(), hton16);
        binary_append(bin, extensions);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
