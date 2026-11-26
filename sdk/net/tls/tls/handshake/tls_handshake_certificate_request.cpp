/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_certificate_request.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate_request.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_request_context_len[] = "request context len";
constexpr char constexpr_request_context[] = "request context";
constexpr char constexpr_extensions_len[] = "extensions len";
constexpr char constexpr_extensions[] = "extensions";

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
        auto& protection = session->get_tls_protection();
        bool post_handshake_certificate_request = false;

        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_client == dir)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        // RFC 9846 4.7.2 / RFC 8446 Verified EID 8795:
        // A CertificateRequest received under the server application traffic
        // keys is post-handshake. The client must have offered post_handshake_auth.
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_server == dir)) {
            uint32 session_status = session->get_session_status();
            bool server_finished = (0 != (session_status_server_finished & session_status));
            bool client_finished = (0 != (session_status_client_finished & session_status));
            if (server_finished && (false == client_finished)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
            post_handshake_certificate_request = server_finished && client_finished;
            if (post_handshake_certificate_request && (0 == session->get_keyvalue().get(session_client_post_handshake_auth))) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
        }

        auto fail_decode = [&]() -> void {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            ret = errorcode_t::bad_format;
        };

        size_t body_end = offsetof_body() + get_body_size();
        if (body_end > size || pos > body_end || body_end - pos < 3) {
            fail_decode();
            __leave2;
        }

        binary_t extensions;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_request_context_len)    //
               << new payload_member(binary_t(), constexpr_request_context)      //
               << new payload_member(uint16(0), true, constexpr_extensions_len)  //
               << new payload_member(binary_t(), constexpr_extensions);          //
            pl.set_reference_value(constexpr_request_context, constexpr_request_context_len);
            pl.set_reference_value(constexpr_extensions, constexpr_extensions_len);

            ret = pl.read(stream, body_end, pos);
            if (errorcode_t::success != ret) {
                fail_decode();
                __leave2;
            }
            pl.get_binary(constexpr_request_context, _request_context);
            pl.get_binary(constexpr_extensions, extensions);
        }

        // RFC 8446 4.4.2: the context is empty in the main handshake.
        // Post-handshake authentication may use a context; the RFC does not
        // require its length to be non-zero.
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_server == dir) && (false == post_handshake_certificate_request) &&
            (false == _request_context.empty())) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            ret = errorcode_t::bad_format;
            __leave2;
        }

        size_t extensions_pos = 0;
        const byte_t* extensions_stream = extensions.empty() ? stream + body_end : extensions.data();
        ret = get_extensions().read(this, dir, extensions_stream, extensions.size(), extensions_pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if ((extensions_pos != extensions.size()) || (pos != body_end)) {
            fail_decode();
            __leave2;
        }

        if (nullptr == get_extensions().get(tls_extension_type_t::signature_algorithms)) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::missing_extension);
            ret = errorcode_t::bad_format;
            __leave2;
        }

        // RFC 9846 4.4.2: request_context values are unique within a connection.
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_server == dir) &&
            (false == session->register_certificate_request_context(_request_context))) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
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

        auto session = get_session();
        auto& protection = session->get_tls_protection();
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_client == dir)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls1_3() && (from_server == dir)) {
            uint32 session_status = session->get_session_status();
            bool server_finished = (0 != (session_status_server_finished & session_status));
            bool client_finished = (0 != (session_status_client_finished & session_status));
            if (server_finished && (false == client_finished)) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            bool post_handshake_certificate_request = server_finished && client_finished;
            if (post_handshake_certificate_request && (0 == session->get_keyvalue().get(session_client_post_handshake_auth))) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            if ((false == post_handshake_certificate_request) && (false == _request_context.empty())) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            if (false == session->register_certificate_request_context(_request_context)) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }

        // The handshake base class writes the TLS/DTLS-specific header;
        // this payload describes the common CertificateRequest body.
        payload pl;
        pl << new payload_member(uint8(_request_context.size()), constexpr_request_context_len)  //
           << new payload_member(_request_context, constexpr_request_context)                    //
           << new payload_member(uint16(extensions.size()), true, constexpr_extensions_len)      //
           << new payload_member(extensions, constexpr_extensions);

        pl.set_reference_value(constexpr_request_context, constexpr_request_context_len);
        pl.set_reference_value(constexpr_extensions, constexpr_extensions_len);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
