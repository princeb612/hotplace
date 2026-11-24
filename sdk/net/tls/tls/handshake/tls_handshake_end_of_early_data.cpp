/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_end_of_early_data.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_end_of_early_data.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_end_of_early_data::tls_handshake_end_of_early_data(tls_session* session) : tls_handshake(tls_handshake_type_t::end_of_early_data, session) {}

tls_handshake_end_of_early_data::~tls_handshake_end_of_early_data() {}

return_t tls_handshake_end_of_early_data::do_preprocess(tls_direction_t dir, tls_io_operation_t opdir) {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& early_state = session->get_session_info(from_server).get_keyvalue();
    bool accepted = (0 != early_state.get(session_early_data_accepted));
    bool already_finished = (0 != early_state.get(session_early_data_finished));
    auto session_status = session->get_session_status();
    bool server_finished = (0 != (session_status_server_finished & session_status));
    bool client_authentication_started = (0 != ((session_status_client_cert | session_status_client_cert_verified) & session_status));
    if ((from_client != dir) || (false == protection.is_kindof_tls13()) || (tls_flow_t::zero_rtt != protection.get_flow()) || (false == accepted) ||
        (false == server_finished) || client_authentication_started || already_finished) {
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
        session->reset_session_status();
        return errorcode_t::handshake_failure;
    }
    return errorcode_t::success;
}

return_t tls_handshake_end_of_early_data::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        {
            protection.calc(session, tls_handshake_type_t::end_of_early_data, dir);
            if (from_client == dir) {
                // EndOfEarlyData is the final record in the client early-data
                // protection epoch. Preserve that epoch's sequence through
                // its decryption, then reset before the first handshake-key
                // record (the client's Finished).
                session->reset_recordno(from_client);
                session->get_session_info(from_server).get_keyvalue().set(session_early_data_finished, 1);
            }
            session->get_session_info(dir).set_status(get_type());

            protection.update_transcript_hash(session, stream + hspos, get_size());
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_end_of_early_data::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    if (0 != get_body_size()) {
        // RFC 8446 4.5.4: EndOfEarlyData is an empty handshake message.
        auto session = get_session();
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::decode_error);
        session->reset_session_status();
        return errorcode_t::bad_format;
    }

    // EndOfEarlyData has no fields to decode. payload::read() treats an
    // empty input as no_data, so the zero-length body is validated above.
    return errorcode_t::success;
}

return_t tls_handshake_end_of_early_data::do_write_body(tls_direction_t dir, binary_t& bin) {
    payload pl;
    return pl.write(bin);
}

}  // namespace net
}  // namespace hotplace
