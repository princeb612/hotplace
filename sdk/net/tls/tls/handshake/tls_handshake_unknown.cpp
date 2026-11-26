/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_unknown.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_unknown.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_unknown::tls_handshake_unknown(tls_handshake_type_t type, tls_session* session) : tls_handshake(type, session) {}

tls_handshake_unknown::~tls_handshake_unknown() {}

return_t tls_handshake_unknown::write(tls_direction_t dir, binary_t& bin) {
    if (tls_handshake_type_t::hello_request == get_type()) {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        const uint32 finished_status = session_status_client_finished | session_status_server_finished;
        bool handshake_finished = (finished_status == (session->get_session_status() & finished_status));
        bool renegotiation_enabled = (0 != session->get_keyvalue().get(session_conf_enable_tls12_renegotiation));
        bool secure_renegotiation = (0 != session->get_keyvalue().get(session_tls12_secure_renegotiation));
        if ((from_server != dir) || (session_type_t::tls != session->get_type()) || (false == protection.is_kindof_tls1_2()) || (false == handshake_finished) ||
            (false == renegotiation_enabled) || (false == secure_renegotiation)) {
            return errorcode_t::bad_request;
        }
    }
    return tls_handshake::write(dir, bin);
}

return_t tls_handshake_unknown::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    (void)stream;
    (void)size;
    (void)pos;
    if (tls_handshake_type_t::hello_request == get_type()) {
        auto session = get_session();
        if (from_server != dir) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
            session->reset_session_status();
            return errorcode_t::unexpected;
        }
        if (0 != get_body_size()) {
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
            session->reset_session_status();
            return errorcode_t::bad_format;
        }
    }
    return errorcode_t::success;
}

return_t tls_handshake_unknown::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        if (tls_handshake_type_t::hello_request == get_type()) {
            const uint32 finished_status = session_status_client_finished | session_status_server_finished;
            bool handshake_finished = (finished_status == (session->get_session_status() & finished_status));
            if ((from_server != dir) || (session_type_t::tls != session->get_type()) || (false == protection.is_kindof_tls1_2()) || (false == handshake_finished)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                ret = errorcode_t::unexpected;
                __leave2;
            }

            bool renegotiation_enabled = (0 != session->get_keyvalue().get(session_conf_enable_tls12_renegotiation));
            bool secure_renegotiation = (0 != session->get_keyvalue().get(session_tls12_secure_renegotiation));
            if ((tls_io_operation_t::read == opdir) && ((false == renegotiation_enabled) || (false == secure_renegotiation))) {
                // RFC 5246 §7.2.2: a client that declines renegotiation
                // responds with the warning-level no_renegotiation alert.
                session->push_alert(dir, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
                __leave2;
            }
            if ((false == renegotiation_enabled) || (false == secure_renegotiation)) {
                ret = errorcode_t::bad_request;
                __leave2;
            }

            session->reset_session_status();
            protection.set_flow(tls_flow_t::renegotiation);
            session->get_session_info(from_client).get_keyvalue().set(session_tls12_renegotiation_ccs, 0);
            session->get_session_info(from_server).get_keyvalue().set(session_tls12_renegotiation_ccs, 0);
            __leave2;
        }

        auto hspos = offsetof_header();
        protection.update_transcript_hash(session, stream + hspos, get_size());
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_unknown::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
