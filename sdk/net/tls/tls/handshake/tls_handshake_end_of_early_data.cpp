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

return_t tls_handshake_end_of_early_data::do_preprocess(tls_direction_t dir) {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& early_state = session->get_session_info(from_server).get_keyvalue();
    bool accepted = (0 != early_state.get(session_early_data_accepted));
    bool already_finished = (0 != early_state.get(session_early_data_finished));
    bool server_finished = (0 != (session_status_server_finished & session->get_session_status()));
    if ((from_client != dir) || !protection.is_kindof_tls13() || (tls_flow_t::zero_rtt != protection.get_flow()) || !accepted || !server_finished || already_finished) {
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
            // EndOfEarlyData switches only the client direction from early
            // traffic keys to handshake traffic keys. It also marks the end
            // of the client early-data phase; subsequent client application
            // data is 1-RTT and must wait for the client's Finished.
            if (from_client == dir) {
                session->get_session_info(from_server).get_keyvalue().set(session_early_data_finished, 1);
            }
            session->reset_recordno(from_client);
            session->get_session_info(dir).set_status(get_type());

            protection.update_transcript_hash(session, stream + hspos, get_size());
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_end_of_early_data::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
