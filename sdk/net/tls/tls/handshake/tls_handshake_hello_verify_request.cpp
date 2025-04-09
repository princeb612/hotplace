/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_version[] = "version";
constexpr char constexpr_cookie_len[] = "cookie len";
constexpr char constexpr_cookie[] = "cookie";

tls_handshake_hello_verify_request::tls_handshake_hello_verify_request(tls_session* session) : tls_handshake(tls_hs_hello_verify_request, session) {}

return_t tls_handshake_hello_verify_request::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.set_item(tls_context_cookie, _cookie);

        session->clear_session_status(session_client_hello);
        session->update_session_status(session_hello_verify_request);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_hello_verify_request::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto& protection = session->get_tls_protection();

        /**
         * RFC 8446 4.2.2.  Cookie
         * struct {
         *     opaque cookie<1..2^16-1>;
         * } Cookie;
         */

        payload pl;
        pl << new payload_member(uint16(0), true, constexpr_version) << new payload_member(uint8(0), constexpr_cookie_len)
           << new payload_member(binary_t(), constexpr_cookie);
        pl.set_reference_value(constexpr_cookie, constexpr_cookie_len);
        pl.read(stream, size, pos);

        pl.get_binary(constexpr_cookie, _cookie);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("  > cookie %s", base16_encode(_cookie).c_str());
            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_hello_verify_request::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto version = get_session()->get_tls_protection().get_lagacy_version();
        payload pl;
        pl << new payload_member(uint16(0), true, constexpr_version) << new payload_member(uint8(_cookie.size()), constexpr_cookie_len)
           << new payload_member(_cookie, constexpr_cookie);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

void tls_handshake_hello_verify_request::set_cookie(const binary_t& cookie) { _cookie = cookie; }

const binary_t& tls_handshake_hello_verify_request::get_cookie() { return _cookie; }

}  // namespace net
}  // namespace hotplace
