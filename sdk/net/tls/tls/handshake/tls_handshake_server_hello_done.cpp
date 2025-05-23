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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_server_hello_done.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_version[] = "version";
constexpr char constexpr_random[] = "random";
constexpr char constexpr_session_id_len[] = "session id len";
constexpr char constexpr_session_id[] = "session id";
constexpr char constexpr_cipher_suite[] = "cipher suite";
constexpr char constexpr_compression_method[] = "compression method";
constexpr char constexpr_extension_len[] = "extension len";
constexpr char constexpr_extension[] = "extension";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_cookie_len[] = "cookie len";
constexpr char constexpr_cookie[] = "cookie";

tls_handshake_server_hello_done::tls_handshake_server_hello_done(tls_session* session) : tls_handshake(tls_hs_server_hello_done, session) {}

return_t tls_handshake_server_hello_done::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }

        auto session = get_session();

        if (session->get_tls_protection().is_kindof_tls12()) {
            auto session_status = session->get_session_status();
            if (0 == (session_status_server_key_exchange & session_status)) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_unexpected_message);
                session->reset_session_status();
                ret = errorcode_t::error_handshake;
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_server_hello_done::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        {
            protection.update_transcript_hash(session, stream + hspos, get_size());
            session->update_session_status(session_status_server_hello_done);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
