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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_end_of_early_data.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_end_of_early_data::tls_handshake_end_of_early_data(tls_session* session) : tls_handshake(tls_hs_end_of_early_data, session) {}

return_t tls_handshake_end_of_early_data::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        {
            protection.calc(session, tls_hs_end_of_early_data, dir);
            session->reset_recordno(from_client);
            session->reset_recordno(from_server);
            session->get_session_info(dir).set_status(get_type());

            protection.update_transcript_hash(session, stream + hspos, get_size());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_end_of_early_data::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
